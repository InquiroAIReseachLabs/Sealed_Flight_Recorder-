#!/usr/bin/env python3
"""check_docs.py: the docs tests (SPEC B1.10 Reproducible claims, B1.12).

Every public doc is held to four rules:

  1. Commands. Every shell block runs or is syntax-checked. A fenced block whose language is sh,
     bash, shell, console or zsh must also say `doc-test` or `doc-syntax`:
       ```sh doc-test      run, from the repository root, with `bash -euo pipefail`; it must
                           exit 0. Blocks of one doc run in order, so a later block may use files
                           an earlier one wrote. A doc runs with `try/` removed first, and `try/`
                           is removed again at the end.
       ```text doc-output  the exact stdout and stderr of the doc-test block above it (prose may
                           sit between them; another fenced block may not).
       ```sh doc-syntax    a command that cannot run in CI (an install, a release step, a unit
                           for another machine): checked with `bash -n` only, and the paragraph
                           just above it must say "not run in CI".
     Every other fenced block must name a language, so no command hides in an unlabelled block.
     A run must leave `git status` unchanged: docs write only into the git-ignored `try/`.
  2. Numbers. Every number of two or more digits in prose (outside fenced blocks, inline code,
     and the generated blocks between `<!-- BEGIN ... -->` and `<!-- END ... -->` markers) needs
     a source in its paragraph: a file of this repository
     named in inline code (a script, a test, a source file), or a constant or test function that
     the Rust, Python or shell sources define, named in inline code. A table or list may take its
     source from the paragraph that introduces it. Allowed without one: a
     version (`1.17.0`, `v1.17`), an RFC number, an item, step or section number, the year after
     "(c)" in a copyright line, and digits that
     are part of a name (R7, SHA-256, aarch64, Ed25519).
  3. Links. Every relative link resolves to a file in the work tree, and an anchor (`#part`)
     to a heading of that file.
  4. Scope. The public docs: every Markdown file that git lists (tracked, or untracked and not
     ignored), except CLAUDEME.md, docs/SPEC.md and docs/DIAGNOSTIC.md (internal records), the
     reports sfr writes (examples/reports/*.sfr.md), and the provenance and license files of the test
     logs (testdata/**/*.provenance.md, testdata/pyulog/).

Usage:
  scripts/check_docs.py              run every rule (commands need target/ and network for cargo)
  scripts/check_docs.py --static     rules 2 to 4 and the block labels and syntax, nothing run
  scripts/check_docs.py --update     run the commands and rewrite each doc-output block
  ... --doc <doc>...                 any of the above for these docs only
  scripts/check_docs.py --self-test
"""

import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEMPT = {"CLAUDEME.md", "docs/SPEC.md", "docs/DIAGNOSTIC.md"}
SHELLS = {"sh", "bash", "shell", "console", "zsh"}
FENCE = re.compile(r"^( {0,3})(`{3,})(.*)$")
TRY_DIR = "try"
# Doc order: the README builds sfr, so it runs first.
FIRST = ["README.md"]


def fail(msg):
    print(f"check_docs.py: {msg}", file=sys.stderr)
    sys.exit(1)


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def listed_files(root):
    return [f for f in git(root, "ls-files", "-z", "-co", "--exclude-standard").split("\0") if f]


def public_docs(root):
    docs = []
    for f in listed_files(root):
        if not f.endswith(".md") or f in EXEMPT:
            continue
        if re.fullmatch(r"testdata/(.+\.provenance\.md|pyulog/.+)|examples/reports/[^/]+\.sfr\.md", f):
            continue
        docs.append(f)
    first = [d for d in FIRST if d in docs]
    return first + sorted(d for d in docs if d not in first)


class Block:
    def __init__(self, doc, line, info, lines, indent, prose_before):
        self.doc, self.line, self.lines, self.indent = doc, line, lines, indent
        words = info.split()
        self.lang = words[0] if words else ""
        self.tags = set(words[1:])
        self.prose_before = prose_before
        self.output = None  # for a doc-test block: its doc-output block

    @property
    def text(self):
        return "".join(line + "\n" for line in self.lines)

    def where(self):
        return f"{self.doc}:{self.line}"


def parse(doc, text):
    """Splits a doc into fenced blocks and prose lines (line number, text)."""
    blocks, prose = [], []
    lines = text.split("\n")
    i = 0
    paragraph, last = [], []
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            prose.append((i + 1, lines[i]))
            if lines[i].strip():
                paragraph.append(lines[i])
            elif paragraph:
                last, paragraph = paragraph, []
            i += 1
            continue
        indent, ticks, info = len(m.group(1)), m.group(2), m.group(3).strip()
        start = i + 1
        body = []
        i += 1
        while i < len(lines):
            close = re.match(r"^ {0,3}(`{3,})\s*$", lines[i])
            if close and len(close.group(1)) >= len(ticks):
                break
            line = lines[i]
            body.append(line[indent:] if line[:indent].strip() == "" else line)
            i += 1
        else:
            raise ValueError(f"{doc}:{start}: unclosed fenced block")
        blocks.append(Block(doc, start, info, body, indent, " ".join(paragraph or last)))
        # A blank line stands in for the block, so the next paragraph starts fresh.
        prose.append((start, ""))
        paragraph, last = [], []
        i += 1
    return blocks, prose


def check_labels(doc, blocks, errors):
    last_test = None
    for b in blocks:
        if not b.lang:
            errors.append(f"{b.where()}: a fenced block must name its language (sh doc-test, text, toml, ...)")
            continue
        if b.lang in SHELLS:
            kinds = b.tags & {"doc-test", "doc-syntax"}
            if len(kinds) != 1:
                errors.append(f"{b.where()}: a {b.lang} block must say exactly one of doc-test or doc-syntax")
                continue
            if "doc-syntax" in kinds:
                if "not run in ci" not in b.prose_before.lower():
                    errors.append(f"{b.where()}: the paragraph above a doc-syntax block must say \"not run in CI\" and why")
                r = subprocess.run(["bash", "-n"], input=b.text, capture_output=True, text=True)
                if r.returncode != 0:
                    errors.append(f"{b.where()}: shell syntax error: {r.stderr.strip()}")
                last_test = None
            else:
                last_test = b
            continue
        if "doc-output" in b.tags:
            if last_test is None:
                errors.append(f"{b.where()}: a doc-output block must follow a doc-test block")
            elif last_test.output is not None:
                errors.append(f"{b.where()}: the doc-test block at line {last_test.line} already has a doc-output block")
            else:
                last_test.output = b
            last_test = None
            continue
        if b.tags & {"doc-test", "doc-syntax"}:
            errors.append(f"{b.where()}: doc-test and doc-syntax are for shell blocks only")
        last_test = None


# ---------------------------------------------------------------------------------------------
# Numbers

def strip_inline_code(line):
    return re.sub(r"(`+)(.+?)\1", lambda m: " " * len(m.group(0)), line)


def inline_code(line):
    return [m.group(2).strip() for m in re.finditer(r"(`+)(.+?)\1", line)]


def link_targets_removed(line):
    # The target of a link is a path or URL, not prose.
    return re.sub(r"\]\([^)]*\)", "]()", line)


def source_names(root):
    """Constants and test functions the sources define."""
    names = set()
    for f in listed_files(root):
        if not re.search(r"\.(rs|py|sh|mjs|js)$", f) or not os.path.isfile(os.path.join(root, f)):
            continue
        try:
            text = open(os.path.join(root, f), encoding="utf-8").read()
        except UnicodeDecodeError:
            continue
        names.update(re.findall(r"\b(?:pub(?:\([a-z]+\))? )?const ([A-Z][A-Z0-9_]+)\b", text))
        names.update(re.findall(r"^([A-Z][A-Z0-9_]+)\s*=", text, re.M))
        names.update(re.findall(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn ([a-z0-9_]+)", text))
        names.update(re.findall(r"\b(?:def|function) ([a-z_][a-z0-9_]*)", text))
    return names


def is_source(token, root, names, files):
    token = token.strip()
    if token in names:
        return True
    path = token.split()[0].rstrip(",.:;")
    if "/" in path or re.search(r"\.(rs|py|sh|toml|ya?ml|mjs|js|json|md|sfr)$", path):
        rel = path[2:] if path.startswith("./") else path
        return rel in files or os.path.exists(os.path.join(root, rel))
    return False


NUMBER = re.compile(r"\d+(?:[.,]\d+)*")
ALLOWED_BEFORE = re.compile(r"(RFC|item|items|step|steps|section|sections|SPEC B|chunk|\(c\))\s?$", re.I)


def bare_numbers(line):
    """Numbers of two or more digits that are not part of a name, version or reference."""
    found = []
    for m in NUMBER.finditer(line):
        s, a, b = m.group(0), m.start(), m.end()
        before = line[a - 1] if a else " "
        after = line[b] if b < len(line) else " "
        if before.isalnum() or before in "_#^/" or after.isalpha() or after == "_":
            continue
        if before == "-" and a >= 2 and line[a - 2].isalpha():
            continue  # SHA-256, UTF-16
        if before == "." and a >= 2 and line[a - 2].isalnum():
            continue
        if re.fullmatch(r"\d+\.\d+\.\d+", s):
            continue  # a version
        if after == "." and b + 1 < len(line) and line[b + 1].isdigit():
            continue
        if ALLOWED_BEFORE.search(line[:a]):
            continue
        digits = re.sub(r"[.,]", "", s)
        if len(digits) < 2:
            continue
        found.append(s)
    return found


def check_numbers(root, doc, prose, errors, names, files):
    # Paragraphs of prose, without generated blocks.
    paragraphs, current, generated = [], [], False
    for n, line in prose:
        if re.match(r"^\s*<!-- BEGIN [a-z-]+:", line):
            generated = True
            continue
        if re.match(r"^\s*<!-- END [a-z-]+ -->", line):
            generated = False
            continue
        if generated:
            continue
        if line.strip():
            current.append((n, line))
        elif current:
            paragraphs.append(current)
            current = []
    if current:
        paragraphs.append(current)
    previous = []
    for para in paragraphs:
        cited = any(is_source(t, root, names, files) for _, l in para for t in inline_code(l))
        if not cited and re.match(r"\s*(\||[-*] |\d+\. )", para[0][1]) and previous:
            cited = any(is_source(t, root, names, files) for _, l in previous for t in inline_code(l))
        if not cited:
            for n, line in para:
                for num in bare_numbers(link_targets_removed(strip_inline_code(line))):
                    errors.append(f"{doc}:{n}: the number {num} has no source in its paragraph "
                                  "(name the script, test, source file or constant it comes from in inline code)")
        previous = para


# ---------------------------------------------------------------------------------------------
# Links

def slug(heading):
    h = re.sub(r"<[^>]+>", "", heading).strip().lower()
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def anchors(text):
    seen, out = {}, set()
    blocks, prose = parse("", text)
    for _, line in prose:
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            s = slug(m.group(1))
            k = seen.get(s, 0)
            out.add(s if k == 0 else f"{s}-{k}")
            seen[s] = k + 1
    return out


def check_links(root, doc, prose, errors):
    for n, line in prose:
        line = strip_inline_code(line)
        targets = re.findall(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)", line)
        targets += re.findall(r"^\s*\[[^\]]+\]:\s*(\S+)", line)
        targets += re.findall(r"href=\"([^\"]+)\"", line)
        for t in targets:
            if re.match(r"^[a-z][a-z0-9+.-]*:", t, re.I):
                continue  # https:, mailto: and other absolute links
            path, _, frag = t.partition("#")
            target = os.path.normpath(os.path.join(os.path.dirname(doc), path)) if path else doc
            full = os.path.join(root, target)
            if not os.path.exists(full):
                errors.append(f"{doc}:{n}: link {t} does not resolve ({target} does not exist)")
                continue
            if frag and target.endswith(".md"):
                if frag not in anchors(open(full, encoding="utf-8").read()):
                    errors.append(f"{doc}:{n}: link {t}: {target} has no heading #{frag}")


# ---------------------------------------------------------------------------------------------
# Commands

def run_doc(root, doc, blocks, errors, update):
    tests = [b for b in blocks if b.lang in SHELLS and "doc-test" in b.tags]
    if not tests:
        return {}
    shutil.rmtree(os.path.join(root, TRY_DIR), ignore_errors=True)
    env = dict(os.environ)
    env.pop("SFR_FORBIDDEN_TERMS_FILE", None)
    new_outputs = {}
    try:
        for b in tests:
            r = subprocess.run(["bash", "-euo", "pipefail", "-c", b.text], cwd=root, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3600)
            out = r.stdout.decode("utf-8", "replace")
            if r.returncode != 0:
                errors.append(f"{b.where()}: the block exited {r.returncode}; its output:\n{out}")
                return new_outputs
            print(f"PASS: {b.where()} ran")
            if b.output is None:
                continue
            if update:
                new_outputs[b.output.line] = (b.output, out)
                continue
            if out.rstrip("\n") != b.output.text.rstrip("\n"):
                diff = "".join(difflib.unified_diff(b.output.text.splitlines(True), out.splitlines(True),
                                                    f"{b.output.where()} (doc)", "actual"))
                errors.append(f"{b.output.where()}: the output of the block at line {b.line} differs:\n{diff}")
            else:
                print(f"PASS: {b.output.where()} output matches")
    finally:
        shutil.rmtree(os.path.join(root, TRY_DIR), ignore_errors=True)
    return new_outputs


def rewrite_outputs(root, doc, new_outputs):
    path = os.path.join(root, doc)
    lines = open(path, encoding="utf-8").read().split("\n")
    # From the last block up, so earlier line numbers stay valid.
    for start in sorted(new_outputs, reverse=True):
        block, out = new_outputs[start]
        end = start + len(block.lines)
        pad = " " * block.indent
        body = [pad + l if l else l for l in out.rstrip("\n").split("\n")]
        lines[start:end] = body
    open(path, "w", encoding="utf-8").write("\n".join(lines))


def check(root, run, update=False, only=None):
    errors = []
    files = set(listed_files(root))
    names = source_names(root)
    docs = [d for d in public_docs(root) if only is None or d in only]
    if not docs:
        fail(f"git listed no public docs under {root}; nothing was checked")
    status_before = git(root, "status", "--porcelain", "--untracked-files=all")
    parsed = {}
    for doc in docs:
        try:
            blocks, prose = parse(doc, open(os.path.join(root, doc), encoding="utf-8").read())
        except ValueError as e:
            errors.append(str(e))
            continue
        parsed[doc] = (blocks, prose)
        check_labels(doc, blocks, errors)
        check_numbers(root, doc, prose, errors, names, files)
        check_links(root, doc, prose, errors)
    if run and not errors:
        for doc in docs:
            blocks, _ = parsed[doc]
            new_outputs = run_doc(root, doc, blocks, errors, update)
            if update and new_outputs:
                rewrite_outputs(root, doc, new_outputs)
                print(f"updated {len(new_outputs)} output block(s) in {doc}")
        status_after = git(root, "status", "--porcelain", "--untracked-files=all")
        if status_after != status_before and not update:
            errors.append("the doc commands changed the work tree (write only into try/):\n"
                          + "".join(difflib.unified_diff(status_before.splitlines(True),
                                                         status_after.splitlines(True), "before", "after")))
    return docs, errors


def self_test():
    tmp = tempfile.mkdtemp()
    try:
        subprocess.run(["git", "init", "-q", tmp], check=True)
        os.makedirs(os.path.join(tmp, "docs"))
        os.makedirs(os.path.join(tmp, "scripts"))
        open(os.path.join(tmp, ".gitignore"), "w").write("/try/\n")
        open(os.path.join(tmp, "scripts/count.sh"), "w").write("#!/bin/sh\nconst() { :; }\n")
        open(os.path.join(tmp, "lib.rs"), "w").write("pub const MAX_THINGS: usize = 64;\n#[test]\nfn things_are_capped() {}\n")
        good = (
            "# Good\n\n## Part two\n\nSee [the other doc](docs/other.md#a-heading) and [part two](#part-two).\n\n"
            "At most 64 things (`MAX_THINGS`). R7, SHA-256, v1.17 and 1.17.0 need no source; nor does RFC 8785.\n\n"
            "```sh doc-test\nmkdir -p try && echo hello > try/x && cat try/x\n```\n\nIt prints:\n\n"
            "```text doc-output\nhello\n```\n\n"
            "Not run in CI: it needs a vehicle.\n\n```sh doc-syntax\nsystemctl enable sfr-seal.service\n```\n\n"
            "| a | b |\n|---|---|\n| 12 | 34 |\n\n"
        )
        # The table above has no source in its paragraph or the one before: one error per number.
        open(os.path.join(tmp, "README.md"), "w").write(good)
        open(os.path.join(tmp, "docs/other.md"), "w").write("# Other\n\n## A heading\n\nCounted by `scripts/count.sh`: 12 and 34.\n")
        docs, errors = check(tmp, run=True)
        assert docs == ["README.md", "docs/other.md"], docs
        assert [e.split(":")[1] for e in errors] == ["27", "27"], errors
        assert not os.path.exists(os.path.join(tmp, "try")), "try/ removed"
        open(os.path.join(tmp, "README.md"), "w").write(good.replace("| a | b |", "From `scripts/count.sh`:\n\n| a | b |"))
        docs, errors = check(tmp, run=True)
        assert errors == [], errors
        cases = [
            ("a wrong output", good.replace("hello\n```\n\n", "goodbye\n```\n\n", 1), "differs"),
            ("a failing block", good.replace("cat try/x", "false"), "exited 1"),
            ("an unlabelled shell block", good.replace("```sh doc-test", "```sh"), "exactly one of doc-test"),
            ("a block with no language", good.replace("```sh doc-test", "```"), "must name its language"),
            ("an unlabelled doc-syntax block", good.replace("Not run in CI: it needs", "It needs"), "not run in CI"),
            ("bad syntax", good.replace("systemctl enable", "if then"), "syntax error"),
            ("a stray output block", good.replace("```sh doc-test\nmkdir", "```text\nmkdir"), "must follow a doc-test"),
            ("a dangling link", good.replace("docs/other.md#", "docs/missing.md#"), "does not resolve"),
            ("a dangling anchor", good.replace("#a-heading", "#no-heading"), "no heading"),
            ("an uncited number", good.replace(" (`MAX_THINGS`)", ""), "the number 64"),
            ("a made-up constant", good.replace("`MAX_THINGS`", "`MAX_OTHER`"), "the number 64"),
            ("a write outside try/", good.replace("mkdir -p try &&", "echo x > stray && mkdir -p try &&"), "changed the work tree"),
        ]
        for name, text, expect in cases:
            open(os.path.join(tmp, "README.md"), "w").write(text.replace("| a | b |", "From `scripts/count.sh`:\n\n| a | b |"))
            for f in ("stray",):
                if os.path.exists(os.path.join(tmp, f)):
                    os.remove(os.path.join(tmp, f))
            _, errors = check(tmp, run=True)
            assert any(expect in e for e in errors), f"{name}: expected {expect!r} in {errors}"
        # --update rewrites the output block from the run.
        open(os.path.join(tmp, "README.md"), "w").write(good.replace("hello\n```\n\n", "stale\n```\n\n", 1)
                                                         .replace("| a | b |", "From `scripts/count.sh`:\n\n| a | b |"))
        check(tmp, run=True, update=True)
        assert "```text doc-output\nhello\n```" in open(os.path.join(tmp, "README.md")).read()
        # Exempt files and generated reports are not public docs; generated blocks are not prose.
        open(os.path.join(tmp, "CLAUDEME.md"), "w").write("```\nanything 1234\n```\n")
        os.makedirs(os.path.join(tmp, "examples/reports"))
        open(os.path.join(tmp, "examples/reports/x.sfr.md"), "w").write("```\n99\n```\n")
        open(os.path.join(tmp, "docs/gen.md"), "w").write("# Gen\n\n<!-- BEGIN tests: written -->\n123 passed\n<!-- END tests -->\n")
        docs, errors = check(tmp, run=False)
        assert "CLAUDEME.md" not in docs and "examples/reports/x.sfr.md" not in docs and errors == [], (docs, errors)
    finally:
        shutil.rmtree(tmp)
    print("PASS: docs self-test (commands run and outputs compared, labels, syntax-only blocks, links and anchors, "
          "number sources, the work tree left unchanged, --update)")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return 0
    only = None
    if "--doc" in argv:
        i = argv.index("--doc")
        only, argv = argv[i + 1:], argv[:i]
    if argv not in ([], ["--static"], ["--update"]) or only == []:
        fail(f"unknown arguments {argv}; see the header of this script")
    docs, errors = check(ROOT, run=argv != ["--static"], update=argv == ["--update"], only=only)
    if errors:
        print("FAIL: docs tests:")
        for e in errors:
            print(f"  {e}")
        return 1
    what = "labels, syntax, numbers and links" if argv == ["--static"] else "every doc command run, outputs, labels, syntax, numbers and links"
    print(f"PASS: docs tests ({what}) in {len(docs)} public docs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
