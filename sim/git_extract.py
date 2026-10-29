"""
Extract per-contribution signals from a real git history.

For each non-merge commit the following are derived, using only information
available at commit time (no hindsight):

    signed          %G? != 'N'  (a signature is present)
    reviewed        committer != author, or a Reviewed-by / Acked-by / Tested-by /
                    Approved-by trailer, or a pull-request reference
                    ("Closes #N", "(#N)", "PR-URL:")  -> an independent person merged it
    tests_included  a path under test/, tests/, testing/, spec/, or named *test*
    sensitive       build system, CI, dependency manifests, release scripts, SECURITY.md
    binary_blob     numstat reports a binary file that is not an image/font/doc asset
    new_dependency  a line added to a "dependencies" block of package.json
    security_weakening   (heuristic, unconfirmed) a REMOVED line in a sensitive file
                    mentions a security control (sandbox, landlock, seccomp, fuzz, sanitizer ...)
    reverted        delayed evidence: emitted for the original author at the time a
                    later commit says "This reverts commit <sha>"

CI results are not stored in git; ci_pass is assumed True for every commit.

Usage: python3 git_extract.py <repo_dir> <out.jsonl>
"""
from __future__ import annotations

import json, re, subprocess, sys
from pathlib import Path

SEP_REC, SEP_F = "\x1e", "\x1f"

SENSITIVE = re.compile(
    r"(^|/)(CMakeLists\.txt|configure\.ac|configure\.in|Makefile\.am|Makefile\.in|meson\.build|"
    r"[^/]*\.m4|[^/]*\.cmake|build-aux/.*|\.github/workflows/.*|\.travis\.yml|appveyor\.yml|"
    r"\.gitlab-ci\.yml|azure-pipelines\.yml|Jenkinsfile|package\.json|package-lock\.json|"
    r"yarn\.lock|SECURITY\.md|release\.sh|[^/]*release[^/]*\.sh|setup\.py|pyproject\.toml)$", re.I)
TESTPATH = re.compile(r"(^|/)(tests?|testing|spec|__tests__)(/|$)|test[^/]*$", re.I)
ASSET = re.compile(r"\.(png|jpe?g|gif|svg|ico|bmp|webp|ttf|otf|woff2?|pdf|mo|gmo|docx?|odt)$", re.I)
SECURITY_KW = re.compile(r"landlock|capsicum|seccomp|pledge|unveil|sandbox|fuzz|sanitiz|asan|ubsan|"
                         r"fstack-protector|fortify_source|relro|pie\b|cosign|sigstore|gpg|signature", re.I)
REVIEW_TRAILER = re.compile(r"^(Reviewed-by|Acked-by|Tested-by|Approved-by|Reviewed-on|PR-URL):", re.I | re.M)
PR_REF = re.compile(r"(Closes|Fixes|Merges)\s+#\d+|\(#\d+\)|pull/\d+", re.I)
REVERTS = re.compile(r"This reverts commit ([0-9a-f]{7,40})", re.I)


def git(repo, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          errors="replace", check=True).stdout


def author_key(name: str, email: str) -> str:
    return name.strip().lower()


def removed_security_lines(repo, sha, files) -> bool:
    out = git(repo, "show", "-U0", "--format=", sha, "--", *files)
    for line in out.splitlines():
        if line.startswith("-") and not line.startswith("---") and SECURITY_KW.search(line):
            return True
    return False


def dependency_added(repo, sha) -> bool:
    out = git(repo, "show", "-U3", "--format=", sha, "--", "package.json")
    in_deps = False
    for line in out.splitlines():
        body = line[1:] if line[:1] in "+- " else line
        if re.search(r'"(dependencies|peerDependencies|optionalDependencies)"\s*:', body):
            in_deps = True
        elif re.search(r"^\s*}", body):
            in_deps = False
        elif in_deps and line.startswith("+") and re.search(r'^\+\s*"[^"]+"\s*:', line):
            return True
    return False


def extract(repo: Path):
    fmt = SEP_REC + SEP_F.join(["%H", "%at", "%an", "%ae", "%cn", "%ce", "%G?", "%B"]) + SEP_F
    raw = git(repo, "log", "--no-merges", "--reverse", "--numstat", f"--format={fmt}")
    events, by_sha = [], {}
    for rec in raw.split(SEP_REC)[1:]:
        parts = rec.split(SEP_F)
        sha, at, an, ae, cn, ce, sig, body = parts[:8]
        numstat = parts[8] if len(parts) > 8 else ""
        files, binaries = [], []
        for line in numstat.strip().splitlines():
            cols = line.split("\t")
            if len(cols) != 3:
                continue
            a, d, path = cols
            if "=>" in path:  # rename: take the new path
                path = re.sub(r"\{[^}]*=> ([^}]*)\}", r"\1", path).split(" => ")[-1]
            files.append(path)
            if a == "-" and d == "-" and not ASSET.search(path):
                binaries.append(path)
        sens_files = [f for f in files if SENSITIVE.search(f)]
        reviewed = (an.strip().lower() != cn.strip().lower()) or bool(REVIEW_TRAILER.search(body)) \
            or bool(PR_REF.search(body))
        ev = dict(
            sha=sha, t=int(at), author=author_key(an, ae), committer=cn,
            subject=body.strip().splitlines()[0] if body.strip() else "",
            signed=sig != "N", reviewed=bool(reviewed),
            tests_included=any(TESTPATH.search(f) for f in files),
            sensitive=bool(sens_files), binary_blob=bool(binaries),
            new_dependency=("package.json" in [Path(f).name for f in files]) and dependency_added(repo, sha),
            security_weakening=bool(sens_files) and removed_security_lines(repo, sha, sens_files),
            n_files=len(files), kind="commit",
        )
        events.append(ev)
        by_sha[sha] = ev
        for m in REVERTS.finditer(body):
            target = next((s for s in by_sha if s.startswith(m.group(1))), None)
            if target:
                events.append(dict(sha=sha + ":revert:" + target, t=int(at), author=by_sha[target]["author"],
                                   kind="reverted", target=target, subject="(reverted) " + by_sha[target]["subject"]))
    return events


if __name__ == "__main__":
    repo, out = Path(sys.argv[1]), Path(sys.argv[2])
    evs = extract(repo)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        for e in evs:
            f.write(json.dumps(e) + "\n")
    authors = {e["author"] for e in evs}
    print(f"{repo.name}: {len(evs)} events, {len(authors)} authors")
