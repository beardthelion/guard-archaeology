"""Exposure resolution: --exposure-file JSON map, else scope-boundary.md.

Ported from holdout's provisional shape (R14, KTD11). Resolution order:
an operator-supplied --exposure-file JSON map ("path:function" -> bucket),
then <target>/.clawpatch/scope-boundary.md TAINT lines, then "unknown".
A malformed or oversized input warns to stderr and is ignored, never
crashes and never partially applies: the file is untrusted input when the
scanned target is third-party code. Auto-read files under
<target>/.clawpatch/ are realpath-confined to the target root; a symlink
escaping the root warns and is ignored.
"""

from __future__ import annotations

import json
import os
import re
import sys

BUCKETS = ("untrusted", "internal", "unknown")
_MAX_BYTES = 1024 * 1024
_TAINT_RE = re.compile(
    r"^\s*[-*]?\s*(\S+):(\S+)\s+TAINT:\s*yes\b(.*)$", re.IGNORECASE
)
_ENTRY_RE = re.compile(r"\bentry=([^\s]+)", re.IGNORECASE)


class ExposureError(Exception):
    pass


def _warn(msg: str) -> None:
    print(f"archaeology: {msg}", file=sys.stderr)


def confined_path(repo_root: str, rel: str):
    """Path under repo_root when it is a file whose realpath stays inside
    the root; None otherwise (a symlink escaping the root warns).
    """
    path = os.path.join(repo_root, rel)
    if not os.path.isfile(path):
        return None
    real = os.path.realpath(path)
    if not real.startswith(os.path.realpath(repo_root) + os.sep):
        _warn(f"ignoring {rel} resolving outside target root")
        return None
    return path


def _load_map(path: str) -> dict:
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            raise ExposureError(f"exposure file {path} oversized")
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except ExposureError:
        raise
    except (OSError, json.JSONDecodeError) as e:
        raise ExposureError(f"cannot read exposure file {path}: {e}")
    if not isinstance(data, dict):
        raise ExposureError(f"exposure file {path} is not a JSON object")
    out = {}
    for k, v in data.items():
        if v not in BUCKETS:
            raise ExposureError(
                f"exposure file {path}: bad bucket {v!r} for {k!r}"
            )
        out[k] = v
    return out


def _parse_scope_boundary(path: str) -> dict:
    """{'path:func': bucket} from TAINT lines, plus entry ids under
    'entry:<key>'."""
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            raise ValueError("scope-boundary.md oversized")
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, ValueError) as e:
        _warn(f"ignoring unreadable scope-boundary.md: {e}")
        return {}
    out = {}
    for line in text.splitlines():
        m = _TAINT_RE.match(line)
        if not m:
            continue
        key = f"{m.group(1)}:{m.group(2)}"
        out[key] = "untrusted"
        e = _ENTRY_RE.search(m.group(3) or "")
        if e:
            out[f"entry:{key}"] = e.group(1)
    return out


def load_exposure(repo_root: str, exposure_file: str = None) -> dict:
    """Resolve the exposure map. Key 'path:function' -> bucket; entry ids
    ride under 'entry:path:function'."""
    if exposure_file:
        try:
            return _load_map(exposure_file)
        except ExposureError as e:
            _warn(f"ignoring exposure file {exposure_file}: {e}")
    sb = confined_path(
        repo_root, os.path.join(".clawpatch", "scope-boundary.md")
    )
    if sb is not None:
        return _parse_scope_boundary(sb)
    return {}


def lookup(emap: dict, path: str, function: str):
    """(bucket, entry) for 'path:function'. 'unknown' is its own bucket,
    never assumed (R14)."""
    key = f"{path}:{function}"
    return emap.get(key, "unknown"), emap.get(f"entry:{key}")
