"""Per-language shape tables, signature normalization, and the sink catalog.

The tables are deliberately thin (R5, precision over recall): anything they
cannot classify is dropped by the extractor, never guessed.

Guard-class vocabulary per SPEC.md Definitions:
bounds, validation, allowlist, auth, escape, type-range, symlink.

Normalized signatures (KTD9): identifiers -> ID, string literals -> STR,
numeric literals -> NUM, call names -> CALL:<family>; the operator and
keyword skeleton is kept, including comparison direction, and a multi-line
statement collapses to one signature.

signature_regex compiles a normalized signature to the git -G ERE used for
pickaxe candidacy (KTD3): ID/NUM/STR/CALL tokens expand to character
classes, literal tokens are escaped, and inter-token spacing becomes
``[ \t]*`` so the pattern matches source text rather than signature text.
For a multi-line guard the caller compiles the signature anchor (the first
raw line's normalized skeleton), since -G cannot match across lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

EXT_TO_LANG = {
    ".go": "go",
    ".rs": "rust",
    ".py": "python",
    ".ts": "tsjs",
    ".tsx": "tsjs",
    ".js": "tsjs",
    ".jsx": "tsjs",
    ".mts": "tsjs",
    ".cts": "tsjs",
    ".mjs": "tsjs",
    ".cjs": "tsjs",
}


def language_for_path(path):
    """Language id for a repo path, or None when the extension is untracked."""
    if not path:
        return None
    dot = path.rfind(".")
    if dot < 0:
        return None
    return EXT_TO_LANG.get(path[dot:].lower())


def basename(dotted):
    """Last segment of a dotted or :: separated callee name."""
    base = dotted.rsplit(".", 1)[-1].rsplit("::", 1)[-1]
    return base.rstrip("!")


def _call_re(name):
    """Bare ``name(`` invocation: not attribute- or ``$``-qualified."""
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"\s*\(")


def _word_re(name):
    """Whole-word mention of ``name`` (not glued to word chars or ``$``).

    Attribute mentions (mod.name, obj.name()) match too: only the bare
    ``name(`` form is a bound call site, so a match that is not a call
    or declaration is a mention, never a callee.
    """
    return re.compile(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])")


# --- language tables ----------------------------------------------------------

_KEYWORDS = {
    "go": frozenset(
        "if else return func var const for range defer go select switch "
        "case default break continue package import type struct interface "
        "map chan fallthrough goto nil true false iota".split()
    ),
    "rust": frozenset(
        "if else return fn let mut const static impl trait mod pub use "
        "struct enum match loop while for break continue async await "
        "unsafe extern move dyn ref where crate self Self super in "
        "true false type as".split()
    ),
    "python": frozenset(
        "if elif else return raise def class for while with as import "
        "from try except finally pass break continue lambda yield async "
        "await global nonlocal del assert in is not and or True False "
        "None".split()
    ),
    "tsjs": frozenset(
        "if else return throw function class const let var new delete "
        "typeof instanceof in of for while do switch case default break "
        "continue try catch finally async await yield this export import "
        "from extends super static get set void true false null "
        "undefined".split()
    ),
}

_LINE_COMMENT = {
    "go": ("//",),
    "rust": ("//",),
    "python": ("#",),
    "tsjs": ("//",),
}

_BLOCK_COMMENT = {
    "go": (("/*", "*/"),),
    "rust": (("/*", "*/"),),
    "python": (),
    "tsjs": (("/*", "*/"),),
}

# Rejection actions that close a conditional-rejection shape, applied to
# string/comment-masked statement text.
_REJECT_RES = {
    "go": (
        re.compile(r"\breturn\b"),
        re.compile(r"\bpanic\s*\("),
        re.compile(r"\blog\.(?:Fatal|Fatalf|Fatalln|Panic)\w*\s*\("),
        re.compile(r"\bos\.Exit\s*\("),
    ),
    "rust": (
        re.compile(r"\breturn\b"),
        re.compile(r"\bpanic!"),
        re.compile(r"\bbail!"),
        re.compile(r"\banyhow!"),
        re.compile(r"\bErr\s*\("),
    ),
    "python": (
        re.compile(r"\braise\b"),
        re.compile(r"\breturn\b"),
        re.compile(r"\bsys\.exit\s*\("),
        re.compile(r"\bexit\s*\("),
    ),
    "tsjs": (
        re.compile(r"\bthrow\b"),
        re.compile(r"\breturn\b"),
        re.compile(r"\bprocess\.exit\s*\("),
    ),
}

# Hard rejections: raise/throw/panic/exit, never a bare 'return'. A
# member-access guard cue ('if cfg.offline: ...') only counts when the
# body actually rejects, so a feature toggle stays dropped.
_HARD_REJECT_RES = {
    lang: tuple(
        r for r in res if r.pattern != r"\breturn\b"
    )
    for lang, res in _REJECT_RES.items()
}

# Constant-declaration heads; group 1 is the bound name. Python accepts a
# bare annotated or plain assignment anywhere (module-level or local).
_DECL_RES = {
    "go": re.compile(
        r"^\s*(?:const|var)\s+([A-Za-z_]\w*)\s*(?:[A-Za-z_][\w\[\]]*\s*)?="
    ),
    "rust": re.compile(
        r"^\s*(?:pub\s+)?(?:const|static|let)\s+(?:mut\s+)?"
        r"([A-Za-z_]\w*)\s*(?::\s*[^=]+?)?\s*="
    ),
    "python": re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::\s*[^=]+?)?\s*=[^=]"),
    "tsjs": re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)"
        r"\s*(?::\s*[^=]+?)?\s*="
    ),
}

# Inside a Go const (...)/var (...) block a bare 'NAME = value' line is a
# constant declaration as well.
_GO_BARE_DECL_RE = re.compile(
    r"^\s*([A-Za-z_]\w*)\s*(?:[A-Za-z_][\w\[\]]*\s*)?=\s*[^=]"
)

_FUNC_RES = {
    "go": (
        re.compile(
            r"^\s*func\s+(?:\(\s*(?P<recv>[*\w.\s]+?)\s*\)\s*)?"
            r"(?P<name>[A-Za-z_]\w*)\s*\("
        ),
    ),
    "rust": (
        re.compile(
            r"^\s*(?:pub(?:\s*\([^)]*\))?\s+|async\s+|unsafe\s+|"
            r"extern\s+\"[^\"]*\"\s+|default\s+|const\s+)*"
            r"fn\s+(?P<name>[A-Za-z_]\w*)"
        ),
    ),
    "tsjs": (
        re.compile(
            r"^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?"
            r"function\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)"
        ),
        re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?"
            r"(?:\(|[A-Za-z_$][\w$]*\s*=>|function)"
        ),
        re.compile(
            r"^\s*(?:(?:public|private|protected|static|async|override|"
            r"get|set|readonly|abstract)\s+)*"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*"
            r"(?::\s*[^{}]+?)?\s*\{"
        ),
    ),
}

_CONTAINER_RES = {
    "go": (),
    "rust": (
        re.compile(
            r"^\s*(?:pub\s+)?(?:unsafe\s+)?impl(?:\s*<[^>]*>)?\s+"
            r"(?P<name>[A-Za-z_][\w:<>, ]*?)(?:\s+for\s+"
            r"(?P<for>[A-Za-z_][\w:<>]*))?\s*(?:where\b.*)?\{?\s*$"
        ),
        re.compile(r"^\s*(?:pub\s+)?mod\s+(?P<name>[A-Za-z_]\w*)\s*\{"),
        re.compile(
            r"^\s*(?:pub\s+)?(?:unsafe\s+)?(?:auto\s+)?trait\s+"
            r"(?P<name>[A-Za-z_]\w*)"
        ),
    ),
    "python": (),
    "tsjs": (
        re.compile(
            r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+"
            r"(?P<name>[A-Za-z_$][\w$]*)"
        ),
    ),
}

_PY_DEF_RE = re.compile(r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)")
_PY_CLASS_RE = re.compile(r"^(?P<indent>[ \t]*)class\s+(?P<name>[A-Za-z_]\w*)")

# TS/JS method-pattern names that are control flow, not declarations.
_TSJS_NON_METHOD = frozenset(
    "if for while switch catch function return else do try with typeof "
    "new case default throw delete void yield await".split()
)

# Sink catalog: dangerous operations whose presence in the guard's scope
# makes the added shape a guard for this tool (R3). Matched against
# string/comment-masked line text; the first match wins.
_SINK_RES = {
    "go": (
        re.compile(r"\bexec\.Command(?:Context)?\s*\("),
        re.compile(
            r"\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|"
            r"RemoveAll|Symlink|Link|Lstat|Stat|Mkdir|MkdirAll|Chmod|"
            r"Rename|ReadDir|Pipe)\s*\("
        ),
        re.compile(r"\bioutil\.(?:ReadFile|WriteFile|TempFile|ReadAll|ReadDir)\s*\("),
        re.compile(
            r"\b(?:Query|QueryContext|QueryRow|QueryRowContext|Exec|"
            r"ExecContext|Prepare)\s*\("
        ),
        re.compile(
            r"\btemplate\.(?:HTML|HTMLAttr|JS|JSStr|URL|CSS|Srcset)\s*\("
        ),
        re.compile(
            r"\bhttp\.(?:Get|Post|PostForm|Do|NewRequest|"
            r"NewRequestWithContext|ServeFile|ServeContent)\s*\("
        ),
        re.compile(r"\bfilepath\.(?:Walk|WalkDir)\s*\("),
        re.compile(r"\b(?:json|xml|yaml|gob)\.[A-Z]?[Uu]nmarshal\w*\s*\("),
        re.compile(r"\b(?:symlink|syscall\.Exec)\s*\("),
    ),
    "rust": (
        re.compile(r"\bCommand::new"),
        re.compile(r"\bprocess::Command\b"),
        re.compile(
            r"\bfs::(?:read|read_to_string|read_dir|write|remove_file|"
            r"remove_dir|remove_dir_all|create_dir|create_dir_all|copy|"
            r"rename|hard_link|symlink|set_permissions|canonicalize|"
            r"metadata|exists)\b"
        ),
        re.compile(r"\bFile::(?:open|create|options)\b"),
        re.compile(r"\bOpenOptions::new\b"),
        re.compile(
            r"\b(?:execute|executemany|query|query_one|query_row|"
            r"prepare|transaction|fetch_all|fetch_one)\s*\("
        ),
        re.compile(r"\.read_to_(?:string|end)\s*\("),
        re.compile(r"\b(?:TcpStream::connect|TcpListener::bind)\b"),
        re.compile(r"\breqwest::(?:get|Client|blocking)\b"),
        re.compile(r"\b(?:eval|system|exec)\s*\("),
    ),
    "python": (
        re.compile(r"\b(?:eval|exec|open|compile|__import__)\s*\("),
        re.compile(
            r"\bos\.(?:system|popen|spawn\w*|exec\w*|remove|unlink|"
            r"removedirs|rename|renames|symlink|link|readlink|mkdir|"
            r"makedirs|chmod|chown|open|fdopen|read|write|listdir|"
            r"scandir|walk|stat|lstat|access|startfile|kill)\s*\("
        ),
        re.compile(
            r"\bos\.path\.(?:join|realpath|abspath|expanduser|expandvars|"
            r"normpath|relpath|islink|isabs|getsize)\s*\("
        ),
        # pathlib.Path filesystem and path ops (attribute calls; the
        # object is a path even when the receiver name is not "path")
        re.compile(
            r"\.(?:joinpath|resolve|absolute|expanduser|relative_to|"
            r"read_text|read_bytes|write_text|write_bytes|symlink_to|"
            r"link_to|hardlink_to|mkdir|rmdir|unlink|rename|replace|"
            r"chmod|lchmod|touch|stat|lstat)\s*\("
        ),
        re.compile(
            r"\bsubprocess\.(?:run|call|Popen|check_call|check_output|"
            r"getoutput|getstatusoutput)\s*\("
        ),
        re.compile(
            r"\bshutil\.(?:copy|copy2|copyfile|copytree|move|rmtree|"
            r"chown)\s*\("
        ),
        re.compile(
            r"\b(?:yaml\.load|pickle\.loads?|marshal\.loads?|"
            r"json\.loads?|shelve\.open|dill\.loads?)\s*\("
        ),
        re.compile(r"\bexecute(?:many|script)?\s*\("),
        re.compile(
            r"\b(?:mark_safe|render_template_string|Markup|"
            r"send_file|sendfile|urlretrieve|urlopen)\s*\("
        ),
        re.compile(
            r"\b(?:requests|httpx|urllib3)\."
            r"(?:get|post|put|delete|head|patch|request)\s*\("
        ),
        re.compile(r"\burllib\.request\."),
        re.compile(r"\.extractall\s*\("),
        re.compile(r"\b(?:tarfile\.open|zipfile\.ZipFile)\s*\("),
        re.compile(r"\bsocket\.socket\s*\("),
        re.compile(r"\binput\s*\("),
    ),
    "tsjs": (
        re.compile(
            r"\b(?:eval|exec|execSync|execFile|execFileSync|spawn|"
            r"spawnSync|fork)\s*\("
        ),
        re.compile(r"\bchild_process\.\w+"),
        re.compile(
            r"\bfs(?:promises)?\.(?:readFile|readFileSync|writeFile|"
            r"writeFileSync|appendFile|appendFileSync|open|openSync|"
            r"unlink|unlinkSync|rmdir|rmdirSync|rm|rmSync|symlink|"
            r"symlinkSync|rename|renameSync|readdir|readdirSync|"
            r"createReadStream|createWriteStream|copyFile|copyFileSync|"
            r"chmod|chmodSync|access|stat|lstat|realpath)\b"
        ),
        re.compile(r"\bnew\s+Function\s*\("),
        re.compile(
            r"\bdocument\.write(?:ln)?\s*\(|\.innerHTML\s*=|"
            r"\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|"
            r"dangerouslySetInnerHTML|\.srcdoc\s*="
        ),
        re.compile(r"\b(?:query|execute|queryRaw|executeRaw|\$queryRaw)\s*\("),
        re.compile(r"\bres\.(?:send|render|sendFile|download|redirect)\s*\("),
        re.compile(r"\b(?:fetch|got)\s*\("),
        re.compile(r"\baxios\.(?:get|post|put|delete|head|patch|request)\s*\("),
        re.compile(r"\bvm\.(?:runIn|runInNewContext|runInThisContext|Script)\b"),
        re.compile(r"\bpath\.(?:join|resolve|normalize)\s*\("),
        re.compile(r"\bnet\.(?:connect|createConnection)\s*\("),
    ),
}


# --- tokenization -------------------------------------------------------------

_STR_RE = re.compile(
    r'[rRbBuUfF]{0,3}"""(?:[^"\\]|\\.|"(?!""))*"""'
    r"|[rRbBuUfF]{0,3}'''(?:[^'\\]|\\.|'(?!''))*'''"
    r'|[rRbBuUfF]{0,3}"(?:[^"\\\n]|\\.)*"'
    r"|[rRbBuUfF]{0,3}'(?:[^'\\\n]|\\.)*'"
    r"|`[^`]*`"
)

_NUM_RE = re.compile(
    r"0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|"
    r"[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][+-]?[0-9]+)?[a-zA-Z]*"
)

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

_OPS = [
    "===", "!==", "<<=", ">>=", "...", "**=", "==", "!=", "<=", ">=",
    "&&", "||", "<<", ">>", "++", "--", "+=", "-=", "*=", "/=", "%=",
    "&=", "|=", "^=", ":=", "->", "=>", "::", "..", "??", "?.", "**",
]
_OP_RE = re.compile("|".join(re.escape(o) for o in _OPS) + "|.", re.DOTALL)


def _starts_comment(text, i, lang):
    for lc in _LINE_COMMENT[lang]:
        if text.startswith(lc, i):
            return True
    for op, _cl in _BLOCK_COMMENT[lang]:
        if text.startswith(op, i):
            return True
    return False


def _skip_comment(text, i, lang):
    for lc in _LINE_COMMENT[lang]:
        if text.startswith(lc, i):
            j = text.find("\n", i)
            return len(text) if j < 0 else j
    for op, cl in _BLOCK_COMMENT[lang]:
        if text.startswith(op, i):
            j = text.find(cl, i + len(op))
            return len(text) if j < 0 else j + len(cl)
    return i + 1


def mask_code(text, lang):
    """Text with string literals and comments blanked to spaces.

    Newlines are preserved so masked offsets line up with the raw text.
    """
    chars = list(text)
    i, n = 0, len(text)
    while i < n:
        if _starts_comment(text, i, lang):
            j = _skip_comment(text, i, lang)
            for k in range(i, j):
                if chars[k] != "\n":
                    chars[k] = " "
            i = j
            continue
        m = _STR_RE.match(text, i)
        if m:
            for k in range(i, m.end()):
                if chars[k] != "\n":
                    chars[k] = " "
            i = m.end()
            continue
        i += 1
    return "".join(chars)


def _lex(text, lang):
    """Token list for statement text: (kind, value).

    Kinds: kw (language keyword), id, num, str, call, op. A call token's
    value is the full dotted/:: callee name.
    """
    kw = _KEYWORDS[lang]
    toks = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if _starts_comment(text, i, lang):
            i = _skip_comment(text, i, lang)
            continue
        m = _STR_RE.match(text, i)
        if m:
            toks.append(("str", m.group(0)))
            i = m.end()
            continue
        m = _NUM_RE.match(text, i)
        if m:
            toks.append(("num", m.group(0)))
            i = m.end()
            continue
        m = _IDENT_RE.match(text, i)
        if m:
            j = m.end()
            name = m.group(0)
            while True:
                if text.startswith("::", j):
                    seg = _IDENT_RE.match(text, j + 2)
                    if seg:
                        name += "::" + seg.group(0)
                        j = seg.end()
                        continue
                elif j < n and text[j] == ".":
                    seg = _IDENT_RE.match(text, j + 1)
                    if seg:
                        name += "." + seg.group(0)
                        j = seg.end()
                        continue
                break
            k = j
            while k < n and text[k] in " \t":
                k += 1
            if name in kw:
                toks.append(("kw", name))
            elif k < n and text[k] == "(":
                toks.append(("call", name))
            elif j < n and text[j] == "!":
                k2 = j + 1
                while k2 < n and text[k2] in " \t":
                    k2 += 1
                if k2 < n and text[k2] == "(":
                    toks.append(("call", name + "!"))
                    i = j + 1
                    continue
                toks.append(("id", name))
            elif "." in name or "::" in name:
                for piece in re.split(r"(\.|::)", name):
                    if piece in (".", "::"):
                        toks.append(("op", piece))
                    elif piece:
                        toks.append(
                            ("kw", piece) if piece in kw else ("id", piece)
                        )
            else:
                toks.append(("id", name))
            i = j
            continue
        m = _OP_RE.match(text, i)
        if m:
            toks.append(("op", m.group(0)))
            i = m.end()
            continue
        i += 1
    return toks


# --- call families -------------------------------------------------------------

_SIZE_NAMES = frozenset(
    "len size length count strlen sizeof cap capacity num number "
    "bytes".split()
)
_ESCAPE_PREFIXES = (
    "escape", "quote", "encode", "encodeuri", "htmlspecialchars",
    "urlencode", "shellescape",
)
_SANITIZER_PREFIXES = (
    "sanitize", "sanitise", "scrub", "clean", "filter", "normalize",
    "normalise", "canonical", "strip", "trim", "purge", "unwrap_or",
)
_AUTH_RE = re.compile(
    r"auth(?!or[sd]?\b)\w*|login|perm(?:i|it|s)|admin|forbidden|unauthor|"
    r"capabilit|access|acl|role|scope|credential",
    re.IGNORECASE,
)
_TYPE_NAMES = frozenset(
    "isinstance issubclass typeof instanceof typecheck asserttype".split()
)
_CHECK_PREFIXES = (
    "check", "validate", "verify", "ensure", "assert", "require", "allow",
    "deny", "permit", "is", "has", "can", "match", "start", "end",
    "contain", "includ", "within", "inside", "safe", "secure", "guard",
    "reject", "legal", "valid", "member",
)
_CALL_FAM_TO_GUARD = {
    "check": "validation",
    "sanitize": "validation",
    "escape": "escape",
    "auth": "auth",
    "type": "type-range",
    "size": "bounds",
}


def call_family(name):
    """CALL:<family> bucket for a callee name (KTD9).

    Known vocabulary maps to its family; anything else keeps its lowered
    basename so unrelated calls do not collapse together.
    """
    base = basename(name).lstrip("_").lower()
    if base in _SIZE_NAMES:
        return "size"
    if base.startswith(_ESCAPE_PREFIXES):
        return "escape"
    if _AUTH_RE.search(base):
        return "auth"
    if base in _TYPE_NAMES:
        return "type"
    if base.startswith(_SANITIZER_PREFIXES):
        return "sanitize"
    if base.startswith(_CHECK_PREFIXES):
        return "check"
    return base


# --- signature normalization -----------------------------------------------------

_WORDLIKE = frozenset({"kw", "id", "num", "str", "call"})


def _wordlike(sig_tok):
    return (
        sig_tok in ("ID", "NUM", "STR")
        or sig_tok.startswith("CALL:")
        or bool(re.match(r"[A-Za-z_$]", sig_tok))
    )


def normalize_statement(lang, stmt_text):
    """KTD9 signature for a statement, or None when it cannot tokenize.

    Identifiers -> ID, strings -> STR, numbers -> NUM, calls -> CALL:<fam>;
    keyword/operator skeleton and comparison direction are kept. Whitespace
    and line joins collapse, so reflowed statements share a signature.
    """
    try:
        toks = _lex(stmt_text, lang)
    except Exception:
        return None
    if not toks:
        return None
    out = []
    for kind, val in toks:
        if kind == "id":
            tok = "ID"
        elif kind == "num":
            tok = "NUM"
        elif kind == "str":
            tok = "STR"
        elif kind == "call":
            tok = f"CALL:{call_family(val)}"
        else:
            tok = val
        if out and _wordlike(out[-1].lstrip()) and _wordlike(tok):
            out.append(" ")
        out.append(tok)
    return "".join(out)


# --- -G regex compiler -----------------------------------------------------------

_SIG_TOK_RE = re.compile(r"CALL:[A-Za-z0-9_-]+|ID|NUM|STR|[A-Za-z_$][\w$]*|.")

# These fragments feed git -G, which compiles POSIX ERE: no (?:...) or
# other Perl-style extensions, plain (...) groups only.
_ID_CLASS = r"[A-Za-z_$][A-Za-z0-9_$]*"
_CALL_CLASS = rf"({_ID_CLASS}(\.|::))*{_ID_CLASS}"
_NUM_CLASS = r"[0-9][A-Za-z0-9._]*"
_STR_CLASS = r"(\"[^\"]*\"|'[^']*'|`[^`]*`)"


def signature_regex(signature):
    """Compile a normalized signature to a git -G ERE (KTD3).

    ID/NUM/STR/CALL tokens expand to character classes; keyword and
    operator tokens are matched literally; spacing becomes ``[ \t]*``
    (``[ \t]+`` between two word-like tokens). The pattern matches source
    text on one line, so multi-line guards are compiled from their
    signature anchor (the first raw line's skeleton).
    """
    toks = [m.group(0) for m in _SIG_TOK_RE.finditer(signature)]
    parts = []
    prev_word = False
    for tok in toks:
        if tok == "ID":
            frag, word = _ID_CLASS, True
        elif tok == "NUM":
            frag, word = _NUM_CLASS, True
        elif tok == "STR":
            frag, word = _STR_CLASS, True
        elif tok.startswith("CALL:"):
            frag, word = _CALL_CLASS, True
        elif tok.isspace():
            continue
        else:
            word = _wordlike(tok)
            frag = (
                r"\b" + re.escape(tok) + r"\b" if word else re.escape(tok)
            )
        parts.append("[ \t]+" if prev_word and word else "[ \t]*")
        parts.append(frag)
        prev_word = word
    if parts and parts[0] == "[ \t]*":
        parts = parts[1:]
    return "".join(parts)


# --- statement classification ------------------------------------------------------

_GUARD_OPS = frozenset({"==", "!=", "<", ">", "<=", ">=", "!", "!==", "==="})
_GUARD_KWS = frozenset({"in", "is", "instanceof", "typeof", "not"})
_GUARD_CALL_FAMILIES = frozenset(
    {"size", "check", "auth", "sanitize", "escape", "type"}
)

_MEMBER_CALLS = frozenset(
    "has contains includes indexof hasownproperty containskey haskey "
    "member lookup".split()
)

_LIT_KWS = frozenset(
    {"true", "false", "True", "False", "None", "nil", "null", "undefined"}
)
_CTOR_CALLS = frozenset(
    "set frozenset list tuple vec hashset hashmap btreeset btreemap "
    "array dict map".split()
)

_SYMLINK_RE = re.compile(
    r"lstat|symlink|islink|readlink|realpath|evalsymlinks|nofollow|toctou",
    re.IGNORECASE,
)
_ALLOWLIST_RE = re.compile(
    r"allow|deny|white.?list|black.?list|block.?list|permit|trusted|"
    r"known.?hosts",
    re.IGNORECASE,
)
_BOUNDS_RE = re.compile(
    r"len|size|length|count|max|min|limit|cap\b|bytes|width|height|"
    r"depth|offset|bound|range",
    re.IGNORECASE,
)
_TYPE_RE = re.compile(
    r"isinstance|issubclass|typeof|instanceof|\btype\b|cast|parse|kind|"
    r"utf-?8|encod",
    re.IGNORECASE,
)


def _cond_tokens(toks):
    """Condition tokens between a leading 'if' and the body opener."""
    if not toks or toks[0] != ("kw", "if"):
        return None
    depth = 0
    for idx in range(1, len(toks)):
        kind, val = toks[idx]
        if kind == "op" and val in ("(", "["):
            depth += 1
        elif kind == "op" and val in (")", "]"):
            depth -= 1
        elif depth == 0 and kind == "op" and val in ("{", ":"):
            return toks[1:idx]
    return toks[1:]


def _guardish(cond_toks):
    """Guard cue in the condition: 'cue', 'member', or None.

    Comparisons, negations, membership tests, and check-family calls are
    unconditional cues. A bare member access (``if obj.attr:``) is a
    weaker cue: it inspects a property of the data
    (``filename.anchor``, ``path.is_symlink``) but also matches feature
    toggles (``if cfg.offline:``), so the caller must additionally
    require a hard rejection before it classifies.
    """
    member = False
    for i, (kind, val) in enumerate(cond_toks):
        if kind == "op" and val in _GUARD_OPS:
            return "cue"
        if kind == "kw" and val in _GUARD_KWS:
            return "cue"
        if kind == "call" and call_family(val) in _GUARD_CALL_FAMILIES:
            return "cue"
        if (kind == "id" and i + 2 < len(cond_toks)
                and cond_toks[i + 1] == ("op", ".")
                and cond_toks[i + 2][0] == "id"):
            member = True
    return "member" if member else None


def _condition_family(cond_toks):
    text = " ".join(v for k, v in cond_toks if k != "str")
    if _SYMLINK_RE.search(text):
        return "symlink"
    if _AUTH_RE.search(text):
        return "auth"
    if _ALLOWLIST_RE.search(text):
        return "allowlist"
    for kind, val in cond_toks:
        if kind == "kw" and val == "in":
            return "allowlist"
        if kind == "call" and basename(val).lower() in _MEMBER_CALLS:
            return "allowlist"
    if _BOUNDS_RE.search(text):
        return "bounds"
    if _TYPE_RE.search(text):
        return "type-range"
    return "validation"


def _literal_rhs(rhs_toks):
    """True when the declared value is a literal or a collection of them."""
    has_lit = False
    for kind, val in rhs_toks:
        if kind in ("num", "str") or (kind == "kw" and val in _LIT_KWS):
            has_lit = True
        elif kind == "call":
            if basename(val).lower() not in _CTOR_CALLS:
                return False
        elif kind == "id" or kind == "kw" or kind == "op":
            continue
    return has_lit


def _constant_decl(lang, masked, toks, const_ctx=False):
    """Bound name plus RHS tokens for a constant declaration, or None."""
    m = _DECL_RES[lang].match(masked)
    if m is None and const_ctx and lang == "go":
        m = _GO_BARE_DECL_RE.match(masked)
    if m is None:
        return None
    name = m.group(1)
    if name in _KEYWORDS[lang]:
        return None
    for idx, tok in enumerate(toks):
        if tok in (("op", "="), ("op", ":=")):
            rhs = toks[idx + 1 :]
            if rhs and _literal_rhs(rhs):
                return name, rhs
            return None
    return None


def _constant_family(name, rhs_toks):
    if _ALLOWLIST_RE.search(name):
        return "allowlist"
    if _SYMLINK_RE.search(name):
        return "symlink"
    if _AUTH_RE.search(name):
        return "auth"
    has_coll = any(
        t in (("op", "["), ("op", "{"), ("op", ","))
        or (t[0] == "call" and basename(t[1]).lower() in _CTOR_CALLS)
        for t in rhs_toks
    )
    n_str = sum(1 for t in rhs_toks if t[0] == "str")
    if has_coll or n_str >= 2:
        return "allowlist"
    if _BOUNDS_RE.search(name):
        return "bounds"
    if _TYPE_RE.search(name):
        return "type-range"
    if any(t[0] == "num" for t in rhs_toks):
        return "bounds"
    return "validation"


def _guard_call_family(toks):
    """Call family of the statement's guard call, or None.

    A bare guard call, an await-wrapped one, or the first guard-family
    call on the right side of an assignment all qualify.
    """
    if toks[0][0] == "call":
        cf = call_family(toks[0][1])
        return cf if cf in _GUARD_CALL_FAMILIES else None
    if len(toks) > 1 and toks[0] == ("kw", "await") and toks[1][0] == "call":
        cf = call_family(toks[1][1])
        return cf if cf in _GUARD_CALL_FAMILIES else None
    seen_assign = False
    for kind, val in toks:
        if (kind, val) in (("op", "="), ("op", ":=")):
            seen_assign = True
            continue
        if kind == "kw" and val in ("defer", "go"):
            return None
        if seen_assign and kind == "call":
            cf = call_family(val)
            if cf in _GUARD_CALL_FAMILIES:
                return cf
            if seen_assign:
                return None
    return None


def classify_statement(lang, stmt_text, const_ctx=False):
    """Classify a statement into (shape, family, meta) or None (R3, R5).

    ``const_ctx`` marks a statement inside a Go const (...)/var (...)
    block, where a bare 'NAME = literal' line declares a constant.
    """
    masked = mask_code(stmt_text, lang)
    toks = _lex(stmt_text, lang)
    if not toks:
        return None
    if toks[0] == ("kw", "if"):
        cond = _cond_tokens(toks)
        if cond is None:
            return None
        cue = _guardish(cond)
        if cue is None:
            return None
        reject = (
            _HARD_REJECT_RES[lang]
            if cue == "member"
            else _REJECT_RES[lang]
        )
        if not any(r.search(masked) for r in reject):
            return None
        return ("conditional-rejection", _condition_family(cond), {})
    decl = _constant_decl(lang, masked, toks, const_ctx=const_ctx)
    if decl is not None:
        name, rhs = decl
        return ("constant-limit", _constant_family(name, rhs),
                {"name": name})
    cf = _guard_call_family(toks)
    if cf is not None:
        return ("validation-call", _CALL_FAM_TO_GUARD.get(cf, "validation"),
                {})
    return None


# --- function attribution -----------------------------------------------------------

@dataclass(frozen=True)
class FuncRange:
    """Lexical extent of a function or container block in one file."""

    start: int  # 0-based line index, inclusive
    end: int  # 0-based line index, inclusive
    name: str
    qualname: str
    kind: str = "func"  # "func" or "container"


def _brace_end(masked, start):
    """Line index where the brace-delimited block starting at start closes."""
    depth = 0
    opened = False
    for j in range(start, len(masked)):
        for ch in masked[j]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
            elif ch == ";" and not opened:
                return j  # bodiless declaration (trait fn, extern decl)
        if opened and depth <= 0:
            return j
    return len(masked) - 1


def _brace_decls(lang, masked):
    """(line, name, kind, recv) declarations found by masked-line patterns."""
    decls = []
    for i, mline in enumerate(masked):
        matched = False
        for cre in _CONTAINER_RES[lang]:
            m = cre.match(mline)
            if m:
                name = m.groupdict().get("for") or m.group("name")
                name = re.sub(r"<.*>", "", name).strip()
                decls.append((i, name, "container", None))
                matched = True
                break
        if matched:
            continue
        for fre in _FUNC_RES[lang]:
            m = fre.match(mline)
            if m:
                name = m.group("name")
                if lang == "tsjs" and name in _TSJS_NON_METHOD:
                    continue
                recv = m.groupdict().get("recv")
                if recv:
                    recv = recv.replace("*", " ").split()
                    recv = recv[-1] if recv else None
                decls.append((i, name, "func", recv))
                break
    return decls


def _find_brace(lang, text):
    lines = text.splitlines()
    masked = [mask_code(l, lang) for l in lines]
    decls = _brace_decls(lang, masked)
    items = []
    for start, name, kind, recv in decls:
        end = _brace_end(masked, start)
        items.append((start, end, name, kind, recv))
    items.sort()
    out = []
    for start, end, name, kind, recv in items:
        enclosing = sorted(
            x for x in items if x[0] < start <= x[1]
        )
        names = [x[2] for x in enclosing]
        if recv:
            names.append(recv)
        sep = "::" if lang == "rust" else "."
        qualname = sep.join(names + [name])
        out.append(
            FuncRange(start=start, end=end, name=name, qualname=qualname,
                      kind=kind)
        )
    return out


def _find_python(text):
    lines = text.splitlines()
    decls = []
    for i, raw in enumerate(lines):
        m = _PY_DEF_RE.match(raw)
        if m:
            decls.append(
                (i, len(m.group("indent").expandtabs(8)), "func",
                 m.group("name"))
            )
            continue
        m = _PY_CLASS_RE.match(raw)
        if m:
            decls.append(
                (i, len(m.group("indent").expandtabs(8)), "container",
                 m.group("name"))
            )
    items = []
    for start, indent, kind, name in decls:
        end = len(lines) - 1
        for j in range(start + 1, len(lines)):
            body = lines[j]
            if not body.strip() or body.lstrip().startswith("#"):
                continue
            ind = len(body.expandtabs(8)) - len(body.expandtabs(8).lstrip())
            if ind <= indent:
                end = j - 1
                break
        items.append((start, end, indent, kind, name))
    out = []
    for start, end, indent, kind, name in items:
        enclosing = sorted(
            x for x in items if x[0] < start <= x[1] and x[2] < indent
        )
        parts = [name]
        for x in reversed(enclosing):
            if x[3] == "func":
                parts.insert(0, "<locals>")
            parts.insert(0, x[4])
        out.append(
            FuncRange(start=start, end=end, name=name,
                      qualname=".".join(parts), kind=kind)
        )
    return out


def find_functions(lang, text):
    """Lexical function/container extents for a file's text."""
    if lang == "python":
        return _find_python(text)
    return _find_brace(lang, text)


# --- sinks and calls --------------------------------------------------------------

def sink_op(lang, line):
    """Catalogued sink operation on a line, or None."""
    masked = mask_code(line, lang)
    for cre in _SINK_RES[lang]:
        m = cre.search(masked)
        if m:
            return m.group(0).strip()
    return None


def call_names(lang, line):
    """Callee basenames invoked on a line, in order."""
    masked = mask_code(line, lang)
    return [
        basename(v) for kind, v in _lex(masked, lang) if kind == "call"
    ]
