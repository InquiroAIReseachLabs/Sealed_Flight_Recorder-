#!/usr/bin/env python3
"""fuzz_phase0.py: the fuzz runs of the chunked code review (docs/review/PLAN.txt, 0.6).

For each target: copy the committed seeds into the git-ignored fuzz/corpus/<target>, run libFuzzer
for a fixed time on the nightly that CI pins, minimize the corpus (cargo fuzz cmin), and keep the
inputs that the minimized corpus has and the seeds lack as new seeds, up to a size cap. Writes
docs/review/FUZZ_RUN.txt: the configuration (so a maintainer can repeat the run), and per target
the executions, the coverage libFuzzer reached, the corpus before and after, the seeds added, and
any crash, timeout or out-of-memory input (kept in fuzz/artifacts/<target>/).

Usage:
  scripts/review/fuzz_phase0.py [--seconds N] [--targets a,b,c] [--seed-cap-bytes N] [--no-seeds]
Defaults: 900 seconds per target; ulog_ingest, sfr_verify, crl_parse; 4 MiB of new seeds per target.
Needs cargo-fuzz and the nightly toolchain from fuzz/README.md.
"""

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NIGHTLY = "nightly-2026-10-18"
OUT = os.path.join(ROOT, "docs/review/FUZZ_RUN.txt")
RUN_ARGS = ["-rss_limit_mb=2048", "-timeout=10", "-max_len=1048576", "-print_final_stats=1"]
WHAT = {
    "ulog_ingest": "the ULog reader and the whole dry-run path (ulog.rs, ingest.rs, events.rs, evaluate.rs, record.rs)",
    "sfr_verify": "the .sfr record reader and verifier (json.rs, verify.rs, merkle.rs)",
    "crl_parse": "the CRL and certificate readers (certs.rs)",
    "rules_parse": "the rules file parser and what reads a rules file (rules.rs, params.rs)",
}


def sh(*cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, **kw)


def parse_log(text):
    """Executions, speed and coverage from libFuzzer's output."""
    d = {}
    m = re.findall(r"^Done (\d+) runs in (\d+) second", text, re.M)
    if m:
        d["runs"], d["seconds"] = int(m[-1][0]), int(m[-1][1])
    for key in ("number_of_executed_units", "average_exec_per_sec", "new_units_added", "slowest_unit_time_sec",
                "peak_rss_mb"):
        m = re.findall(rf"^stat::{key}:\s+(\d+)", text, re.M)
        if m:
            d[key] = int(m[-1])
    last = None
    for line in text.splitlines():
        m = re.match(r"#\d+\s+\w+\s+cov: (\d+) ft: (\d+) corp: (\d+)/(\d+)([A-Za-z]*)", line)
        if m:
            last = m
    if last:
        d["cov"], d["ft"], d["corp"], d["corp_size"] = int(last[1]), int(last[2]), int(last[3]), f"{last[4]}{last[5]}"
    return d


def dir_stats(path):
    n = size = 0
    if os.path.isdir(path):
        for f in os.listdir(path):
            p = os.path.join(path, f)
            if os.path.isfile(p):
                n += 1
                size += os.path.getsize(p)
    return n, size


def digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def add_seeds(target, cap):
    """Inputs of the minimized corpus that the seed directory lacks, smallest first, up to cap bytes."""
    seeds, corpus = os.path.join(ROOT, "fuzz/seeds", target), os.path.join(ROOT, "fuzz/corpus", target)
    have = {digest(os.path.join(seeds, f)) for f in os.listdir(seeds)} if os.path.isdir(seeds) else set()
    os.makedirs(seeds, exist_ok=True)
    new = []
    for f in os.listdir(corpus):
        p = os.path.join(corpus, f)
        d = digest(p)
        if os.path.isfile(p) and d not in have:
            new.append((os.path.getsize(p), d, p))
    new.sort()
    added = used = 0
    for size, d, p in new:
        if used + size > cap:
            continue
        shutil.copyfile(p, os.path.join(seeds, f"corpus_{d[:12]}"))
        used += size
        added += 1
    return added, used, len(new)


def main(argv):
    seconds, targets, cap, keep = 900, ["ulog_ingest", "sfr_verify", "crl_parse"], 4 * 1024 * 1024, True
    a = argv[1:]
    while a:
        x = a.pop(0)
        if x == "--seconds":
            seconds = int(a.pop(0))
        elif x == "--targets":
            targets = a.pop(0).split(",")
        elif x == "--seed-cap-bytes":
            cap = int(a.pop(0))
        elif x == "--no-seeds":
            keep = False
        else:
            print(__doc__)
            return 2
    ver = sh("cargo", f"+{NIGHTLY}", "fuzz", "--version").stdout.strip()
    rustc = sh("rustc", f"+{NIGHTLY}", "--version").stdout.strip()
    cpu = ""
    try:
        cpu = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name"))
    except (OSError, StopIteration):
        pass
    commit = sh("git", "rev-parse", "HEAD").stdout.strip()
    lines = ["Fuzz runs of Phase 0 (docs/review/PLAN.txt, 0.6)", "",
             f"Commit:      {commit}", f"Toolchain:   {rustc}", f"cargo-fuzz:  {ver}",
             f"Host:        {platform.machine()}, {os.cpu_count()} cores, {cpu}",
             f"Each target: {seconds} seconds, one worker, from the committed seeds in fuzz/seeds/<target>/",
             "Command:     cargo +%s fuzz run <target> fuzz/corpus/<target> -- -max_total_time=%d %s" % (
                 NIGHTLY, seconds, " ".join(RUN_ARGS)),
             "Minimize:    cargo +%s fuzz cmin <target>" % NIGHTLY, ""]
    bad = False
    for t in targets:
        corpus = os.path.join(ROOT, "fuzz/corpus", t)
        shutil.rmtree(corpus, ignore_errors=True)
        os.makedirs(corpus)
        for f in os.listdir(os.path.join(ROOT, "fuzz/seeds", t)):
            shutil.copyfile(os.path.join(ROOT, "fuzz/seeds", t, f), os.path.join(corpus, f))
        seed_n, seed_size = dir_stats(os.path.join(ROOT, "fuzz/seeds", t))
        art = os.path.join(ROOT, "fuzz/artifacts", t)
        before_art = set(os.listdir(art)) if os.path.isdir(art) else set()
        print(f"== {t}: {seconds} s", flush=True)
        t0 = time.time()
        r = sh("cargo", f"+{NIGHTLY}", "fuzz", "run", t, os.path.join("fuzz/corpus", t), "--",
               f"-max_total_time={seconds}", *RUN_ARGS)
        wall = int(time.time() - t0)
        log = r.stdout + "\n" + r.stderr
        with open(os.path.join(ROOT, "fuzz", f"phase0-{t}.log"), "w") as fh:
            fh.write(log)
        d = parse_log(log)
        found = sorted(set(os.listdir(art)) - before_art) if os.path.isdir(art) else []
        n_before, s_before = dir_stats(corpus)
        cm = sh("cargo", f"+{NIGHTLY}", "fuzz", "cmin", t)
        n_after, s_after = dir_stats(corpus)
        added = (0, 0, 0)
        if keep and not found and cm.returncode == 0:
            added = add_seeds(t, cap)
        lines += [f"== {t}: {WHAT.get(t, '')}",
                  f"  exit status          {r.returncode}{'' if r.returncode == 0 else '  (a finding or a failure to run: see the log)'}",
                  f"  wall seconds         {wall}",
                  f"  executions           {d.get('number_of_executed_units', d.get('runs', 'n/a'))}",
                  f"  executions/second    {d.get('average_exec_per_sec', 'n/a')}",
                  f"  coverage (edges)     {d.get('cov', 'n/a')}",
                  f"  features             {d.get('ft', 'n/a')}",
                  f"  peak rss (MB)        {d.get('peak_rss_mb', 'n/a')}",
                  f"  seeds at start       {seed_n} files, {seed_size} bytes",
                  f"  corpus at end        {n_before} files, {s_before} bytes",
                  f"  after cmin           {n_after} files, {s_after} bytes",
                  f"  new seeds committed  {added[0]} files, {added[1]} bytes (of {added[2]} new inputs, cap {cap} bytes)",
                  f"  crashes, timeouts, out-of-memory inputs: {', '.join(found) if found else 'none'}", ""]
        if r.returncode != 0 or found:
            bad = True
    with open(OUT, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {os.path.relpath(OUT, ROOT)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
