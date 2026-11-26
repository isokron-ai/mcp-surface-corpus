"""What `uv run` would install for an MCP Bundle of server type uv (src/targets.mjs launchPlan, kind mcpb), as a pip
requirements file. Ours, from the read-only tools volume; it runs in an install container (the python image) with
`python -I`, and reads <bundle>/pyproject.toml as data (tomllib), never imports or runs anything of the bundle.

    python -I pyproject-reqs.py <bundle> <requirements out> [extra ...]

A project that declares a build system is installed itself (`<bundle>[extras]`, as uv installs the project); otherwise
its [project] dependencies and those of the extras asked for. Every requirement must be one line of PEP 508 text that
pip cannot read as an option (no line starting with -, no " -" anywhere): a requirements file is not a place for
--index-url. No direct reference (`name @ <url>`, `file:`) in them or in build-system.requires: everything comes from
PyPI, though the install's proxy also lets GitHub's release hosts through (the bundle's own download). Prints one line, { ok, requirements, project } and exits 0, or { error } and exits 1:
    no_pyproject        the bundle has no pyproject.toml
    pyproject_unreadable  not TOML this reads, or over 1 MiB
    bad_requirement     a dependency that is not plain PEP 508 text
"""
import json
import os
import re
import sys

try:
    import tomllib
except ImportError:  # Python < 3.11: not our image
    print(json.dumps({"error": "pyproject_unreadable", "why": "no tomllib"}))
    sys.exit(1)

REQ = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}(\[[A-Za-z0-9._,\s-]{0,200}\])?\s*(\([^()\n]{0,200}\))?[^\n\r\x00]{0,400}$")
EXTRA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$")


def direct(r):
    """A PEP 508 direct reference or URL in the part before any marker."""
    head = r.split(";", 1)[0]
    return "@" in head or "://" in head or "file:" in head.lower()


def fail(code, **kw):
    print(json.dumps({"error": code, **kw}))
    sys.exit(1)


def main(argv):
    if len(argv) < 2 or not argv[0].startswith("/") or not argv[1].startswith("/"):
        fail("usage")
    root, out, extras = argv[0], argv[1], argv[2:]
    if not all(EXTRA.match(e) for e in extras):
        fail("usage")
    path = os.path.join(root, "pyproject.toml")
    if os.path.islink(path) or not os.path.isfile(path):
        fail("no_pyproject")
    if os.path.getsize(path) > 1024 * 1024:
        fail("pyproject_unreadable", why="over 1 MiB")
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    except Exception as e:  # noqa: BLE001 - any parse failure is the same answer
        fail("pyproject_unreadable", why=type(e).__name__)
    project = doc.get("project") if isinstance(doc.get("project"), dict) else {}
    if isinstance(doc.get("build-system"), dict):
        reqs = [root + ("[" + ",".join(extras) + "]" if extras else "")]
        built = True
    else:
        deps = project.get("dependencies") or []
        opt = project.get("optional-dependencies") or {}
        if not isinstance(deps, list) or not isinstance(opt, dict):
            fail("bad_requirement")
        reqs = list(deps)
        for e in extras:
            more = opt.get(e) or []
            if not isinstance(more, list):
                fail("bad_requirement")
            reqs += more
        built = False
    for r in reqs[1 if built else 0:]:
        if not isinstance(r, str) or not REQ.match(r) or r.lstrip().startswith("-") or re.search(r"\s-", r):
            fail("bad_requirement")
        # A direct reference (`name @ https://...`, `file:`) is fetched from wherever it names, not from PyPI: refused.
        if direct(r):
            fail("bad_requirement", why="direct reference")
    # The same for what a project's build needs (pip fetches build-system.requires before it builds).
    if built:
        bs = doc.get("build-system", {}).get("requires") or []
        if not isinstance(bs, list) or any(not isinstance(r, str) or direct(r) or r.lstrip().startswith("-") for r in bs):
            fail("bad_requirement", why="build-system.requires")
    if len(reqs) > 200:
        fail("bad_requirement", why="over 200 requirements")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(reqs) + ("\n" if reqs else ""))
    print(json.dumps({"ok": True, "requirements": len(reqs), "project": built}))


if __name__ == "__main__":
    main(sys.argv[1:])
