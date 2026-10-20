#!/usr/bin/env python3
"""T3 Tamper tests, each separately, verified with --pubkey and --ulog (the report beside the record is checked too).

Needs the records T2 wrote ($A_WORK/t02). Exits 0 only if every case fails verification and names what changed."""
import os, shutil, struct, subprocess, sys, json, re
R = os.environ["A_REPO"]; SFR = os.environ["A_SFR"]; AW = os.environ["A_WORK"]; W = AW + "/t03"
shutil.rmtree(W, ignore_errors=True); os.makedirs(W)
KEYDIR = AW + "/t02/key"          # the key the golden records were sealed with
NAME = "v1.17.0_vtol_transition"
REC = f"{AW}/t02/out/{NAME}/vtol_transition.sfr"
LOG = f"{R}/testdata/sitl/v1.17.0/vtol_transition.ulg"
OTHER = f"{R}/testdata/sitl/v1.17.0/mc_flight_1.ulg"

def run(args, cwd=R):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr

def verify(rec, log, pub=KEYDIR + "/sfr.pub"):
    cmd = [SFR, "verify", rec, "--pubkey", pub, "--allow-evaluation-key", "--ulog", log]
    rc, out = run(cmd)
    return cmd, rc, out

def fresh(tag):
    d = f"{W}/{tag}"; os.makedirs(d)
    shutil.copy(REC, d + "/vtol_transition.sfr"); shutil.copy(REC + ".md", d + "/vtol_transition.sfr.md")
    return d

results = []
def case(tag, desc, rec, log, expect_in, pub=KEYDIR + "/sfr.pub"):
    cmd, rc, out = verify(rec, log, pub)
    integ = next((l for l in out.splitlines() if l.startswith("Integrity")), "(no Integrity line)")
    also = [l.strip() for l in out.splitlines() if l.strip().startswith("also:")]
    failed = rc != 0 and "VERIFIED" not in integ
    named = any(re.search(e, out) for e in expect_in)
    status = "PASS" if failed and named else ("FAIL: verify passed" if not failed else "FAIL: did not name the change")
    results.append((tag, desc, status))
    print(f"\n[{tag}] {desc}\n  command: sfr verify {os.path.relpath(rec, W)} --pubkey sfr.pub --allow-evaluation-key --ulog {os.path.relpath(log, W) if log.startswith(W) else log.replace(R+'/','')}\n  exit {rc}\n  {integ[:230]}")
    for a in also[:2]: print("  " + a[:200])
    print(f"  => {status}")

orig = open(LOG, "rb").read()
def log_with(tag, data):
    d = f"{W}/{tag}"; os.makedirs(d, exist_ok=True)
    p = d + "/vtol_transition.ulg"; open(p, "wb").write(data); return p

# ULog messages: 16-byte header, then (size u16, type u8, payload). Find data-section 'D' messages.
def messages(b):
    pos, out = 16, []
    while pos + 3 <= len(b):
        size = struct.unpack("<H", b[pos:pos+2])[0]; t = b[pos+2:pos+3]
        out.append((pos, 3 + size, t)); pos += 3 + size
    return out
msgs = messages(orig)
dmsgs = [m for m in msgs if m[2] == b"D"]
print("log:", len(orig), "bytes,", len(msgs), "messages,", len(dmsgs), "data messages")

# 1. flip one byte
for tag, off, desc in [("1a", 100, "one byte flipped in the definitions section"), ("1b", dmsgs[500][0] + dmsgs[500][1] - 1, "one byte flipped in a data message payload"), ("1c", len(orig) - 1, "the last byte flipped")]:
    b = bytearray(orig); b[off] ^= 0x01
    case(tag, f"T3.1 {desc} (offset {off})", REC, log_with(tag, bytes(b)), [r"log digest mismatch", r"log no longer parses"])
# 2. truncate
for tag, n, desc in [("2a", len(orig) - 1, "one byte removed from the end"), ("2b", len(orig) // 2, "cut in half"), ("2c", 16, "header only")]:
    case(tag, f"T3.2 truncated: {desc} ({n} bytes)", REC, log_with(tag, orig[:n]), [r"log digest mismatch", r"log no longer parses"])
# 3. append
for tag, extra, desc in [("3a", b"\x00", "one zero byte"), ("3b", b"APPENDED-BYTES" * 10, "140 bytes of text")]:
    case(tag, f"T3.3 appended: {desc}", REC, log_with(tag, orig + extra), [r"log digest mismatch", r"log no longer parses"])
# 4. remove / reorder a message
m = dmsgs[1000]
case("4a", f"T3.4 one data message removed (at offset {m[0]}, {m[1]} bytes)", REC, log_with("4a", orig[:m[0]] + orig[m[0]+m[1]:]), [r"log digest mismatch"])
a, b2 = dmsgs[1000], dmsgs[1001]
swapped = orig[:a[0]] + orig[b2[0]:b2[0]+b2[1]] + orig[a[0]:a[0]+a[1]] + orig[b2[0]+b2[1]:]
case("4b", "T3.4 two adjacent data messages swapped", REC, log_with("4b", swapped), [r"log digest mismatch"])
# 5. a different log
case("5", "T3.5 a different golden log (mc_flight_1) given as the log", REC, OTHER, [r"log digest mismatch", r"parameter \S+: sealed", r"firmware"])
# 6. edit any field of the .sfr (nothing signed again)
text = open(REC, encoding="utf-8").read()
edits = [("6a", 'a COMMAND event field (command 211 -> 311)', '"command":211,', '"command":311,'),
         ("6b", 'a configuration parameter (MPC_XY_VEL_MAX 8 -> 9)', '"MPC_XY_VEL_MAX":"f32:8"', '"MPC_XY_VEL_MAX":"f32:9"'),
         ("6c", 'the overall status (PASS -> FAIL)', '"status":"PASS"', '"status":"FAIL"'),
         ("6d", 'a rule result (R4 PASS -> FAIL)', '"id":"R4"', '"id":"R9"'),
         ("6e", 'the claimed seal time', '"time_utc":"2026-10-18T15:00:00Z"', '"time_utc":"2020-01-01T00:00:00Z"'),
         ("6f", 'the log file name in the record', '"file_name":"vtol_transition.ulg"', '"file_name":"other_vehicle.ulg"'),
         ("6g", 'the key custody word', '"key_custody":"file-evaluation"', '"key_custody":"pkcs11-token"'),
         ("6h", 'the embedded rules text', 'required topics present', 'required topics PRESENT')]
for tag, desc, a_, b_ in edits:
    if a_ not in text: print(f"[{tag}] SKIPPED: pattern not found: {a_}"); results.append((tag, desc, "FAIL: pattern missing")); continue
    d = fresh(tag); open(d + "/vtol_transition.sfr", "w", encoding="utf-8").write(text.replace(a_, b_, 1))
    case(tag, f"T3.6 edited .sfr: {desc}", d + "/vtol_transition.sfr", LOG, [r"Merkle root mismatch", r"canonical", r"signature", r"rules"])
# 7. edit a line of the .sfr.md
md = open(REC + ".md", encoding="utf-8").read().split("\n")
for tag, idx, desc in [("7a", 7, "line 8 (the status line)"), ("7b", 14, "a rules table row"), ("7c", len(md) - 4, "a line near the end")]:
    d = fresh(tag); lines = list(md); lines[idx] = lines[idx] + " (edited)"
    open(d + "/vtol_transition.sfr.md", "w", encoding="utf-8").write("\n".join(lines))
    case(tag, f"T3.7 edited .sfr.md: {desc}", d + "/vtol_transition.sfr", LOG, [r"report .* line \d+ differs"])
# 8. wrong public key
rc, _ = run([SFR, "keygen", "--evaluation-only", "--out", W + "/wrongkey"])
case("8", "T3.8 verified with the wrong public key", REC, LOG, [r"not by the given public key", r"signed by key"], pub=W + "/wrongkey/sfr.pub")
# 9. reseal a doctored log with a fresh key, verify against the original key
b = bytearray(orig); b[dmsgs[500][0] + dmsgs[500][1] - 1] ^= 0x01
dl = log_with("9", bytes(b))
rc, out = run([SFR, "seal", dl, "--rules", "examples/rules.default.toml", "--baseline", "testdata/baselines/v1.17.0_vtol_transition.params", "--key", W + "/wrongkey/sfr.key", "--evaluation-only", "--out", W + "/9/out"])
print(f"\n(T3.9 setup: doctored log sealed with a fresh key, seal exit {rc})")
case("9", "T3.9 doctored log resealed with a fresh key, verified against the ORIGINAL key", W + "/9/out/vtol_transition.sfr", dl, [r"not by the given public key", r"signed by key"])
# 9b: the same record, verified against the fresh key, passes (the attack is only "valid" for its own key)
cmd, rc2, out2 = verify(W + "/9/out/vtol_transition.sfr", dl, W + "/wrongkey/sfr.pub")
print(f"  (control: the same record against the fresh key: exit {rc2}, {next(l for l in out2.splitlines() if l.startswith('Integrity'))})")

print("\nSUMMARY"); 
bad = [r for r in results if r[2] != "PASS"]
for t, d, s in results: print(f"  {t:3} {s:6} {d}")
print(f"\n{len(results)} cases, {len(results)-len(bad)} fail-as-required, {len(bad)} cases that did NOT fail or did not name the change")
print("RESULT: PASS" if not bad else "RESULT: FAIL (%d)" % len(bad))
sys.exit(1 if bad else 0)
