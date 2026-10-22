import itertools
import json
import os
import subprocess
import sys
from dataclasses import dataclass

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

BASE_EPOCH = 1_700_000_000

# Pinned commit environment: fixture SHAs must be identical across machines,
# so ambient gitconfig (signing, user identity, init defaults) is fully
# neutralized and every commit carries explicit identity plus dates.
GIT_ENV = {
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_AUTHOR_NAME": "Archaeology Test",
    "GIT_AUTHOR_EMAIL": "archaeology-test@example.invalid",
    "GIT_COMMITTER_NAME": "Archaeology Test",
    "GIT_COMMITTER_EMAIL": "archaeology-test@example.invalid",
}


@dataclass
class BuiltRepo:
    root: str
    shas: list


def run_git(root, *argv, env_extra=None, check=True):
    """Run a git command in a fixture repo under the pinned environment."""
    env = dict(os.environ)
    env.update(GIT_ENV)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["git", "-C", str(root), *[str(a) for a in argv]],
        env=env,
        capture_output=True,
        text=True,
    )
    if check:
        assert proc.returncode == 0, (
            f"git {' '.join(str(a) for a in argv)} failed: {proc.stderr}"
        )
    return proc


def commit_env(index):
    stamp = f"@{BASE_EPOCH + index} +0000"
    return {"GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}


@pytest.fixture
def make_repo(tmp_path):
    """Build a git repo from a declarative commit script.

    Each script entry: {files: {path: content}, message: str,
    renames: [(old, new)], deletions: [path], modes: {path: mode},
    tag: "name", allow_empty: bool}. Returns BuiltRepo(root, shas).
    """
    counter = itertools.count()

    def _make(commits, name=None):
        root = tmp_path / (name or f"repo{next(counter)}")
        root.mkdir(parents=True)
        run_git(
            root,
            "-c",
            "init.defaultBranch=main",
            "init",
            "-q",
            "--object-format=sha1",
        )
        for i, spec in enumerate(commits):
            for rel, content in spec.get("files", {}).items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, bytes):
                    p.write_bytes(content)
                else:
                    p.write_text(content)
            for rel, mode in spec.get("modes", {}).items():
                os.chmod(root / rel, mode)
            for old, new in spec.get("renames", []):
                (root / new).parent.mkdir(parents=True, exist_ok=True)
                run_git(root, "mv", old, new)
            for rel in spec.get("deletions", []):
                run_git(root, "rm", "-q", rel)
            run_git(root, "add", "-A")
            args = ["commit", "-q", "-m", spec["message"]]
            if spec.get("allow_empty"):
                args.append("--allow-empty")
            run_git(root, *args, env_extra=commit_env(i))
            if spec.get("tag"):
                run_git(root, "tag", spec["tag"])
        shas = run_git(root, "rev-list", "--reverse", "HEAD").stdout.split()
        return BuiltRepo(str(root), shas)

    return _make


@pytest.fixture
def read_jsonl():
    def _read(path):
        with open(path) as fh:
            return [json.loads(line) for line in fh if line.strip()]

    return _read
