#!/usr/bin/env python3
"""T4 Verify with no trusted key must print NOT CHECKED and exit non-zero. T5 Versions and formats: the PX4 range,
--allow-untested-version, malformed and damaged logs (a log that ends in the middle of a record is sealed, stating
where), ArduPilot and MAVLink files. Needs the key T2 made."""
import os, shutil, struct, subprocess, json, random, sys
R=os.environ["A_REPO"]; SFR=os.environ["A_SFR"]; AW=os.environ["A_WORK"]; W=AW+"/t04_05"; shutil.rmtree(W, ignore_errors=True); os.makedirs(W)
KEY=AW+"/t02/key"
FAILS=[]
def expect(cond, text):
    print("  "+("PASS: " if cond else "FAIL: ")+text)
    if not cond: FAILS.append(text)
def run(args, cwd=R):
    p=subprocess.run(args,cwd=cwd,capture_output=True,text=True,errors="replace"); return p.returncode,(p.stdout+p.stderr)
def show(title, cmd, rc, out, n=6, verdict=None):
    print(f"\n[{title}]\n  command: {' '.join(cmd)}\n  exit: {rc}")
    for l in out.strip().splitlines()[:n]: print("  | "+l[:240])
    if verdict: print("  =>", verdict)
print("=== T4: verify with no --pubkey and no --trust-anchor ===")
rec=AW+"/t02/out/v1.17.0_vtol_transition/vtol_transition.sfr"
for extra in ([], ["--ulog","testdata/sitl/v1.17.0/vtol_transition.ulg"], ["--json"]):
    cmd=["sfr","verify",rec]+extra; rc,out=run([SFR]+cmd[1:])
    ok = rc!=0 and "NOT CHECKED" in out and "VERIFIED" not in out
    show("T4 "+" ".join(extra or ["(plain)"]),cmd,rc,out,8,"PASS" if ok and rc==4 else "FAIL"); expect(ok and rc==4, "T4 "+" ".join(extra or ["(plain)"])+": NOT CHECKED, exit 4, never VERIFIED")
print("\n=== T5: versions and formats ===")
# patch ver_sw_release in a copy of the vtol_transition log
src=open(f"{R}/testdata/sitl/v1.17.0/vtol_transition.ulg","rb").read()
key=b"uint32_t ver_sw_release"; i=src.index(key); val=i+len(key)
assert src[val:val+4]==struct.pack("<I",0x011100ff), src[val:val+4].hex()
def with_ver(major,minor,patch=0):
    b=bytearray(src); b[val:val+4]=struct.pack("<I",(major<<24)|(minor<<16)|(patch<<8)|0xff); return bytes(b)
def seal(tag, data, extra=()):
    d=f"{W}/{tag}"; os.makedirs(d,exist_ok=True); p=f"{d}/flight.ulg"; open(p,"wb").write(data)
    cmd=[SFR,"seal",p,"--rules","examples/rules.default.toml","--baseline","testdata/baselines/v1.17.0_vtol_transition.params","--key",KEY+"/sfr.key","--evaluation-only","--seal-time","2026-10-18T15:00:00Z","--out",d+"/out",*extra]
    rc,out=run(cmd); return d,p,rc,out
for ver in ((1,14),(1,15),(1,16),(1,17)):
    d,p,rc,out=seal(f"v{ver[0]}{ver[1]}",with_ver(*ver))
    wrote=os.path.exists(d+"/out/flight.sfr")
    show(f"T5 PX4 {ver[0]}.{ver[1]} (golden v1.17 log with ver_sw_release patched; real logs exist only for 1.14.4 and 1.17.0)",["sfr","seal","flight.ulg","...",],rc,out,3,f"record written: {wrote}"); expect(wrote and rc in (0,1,2), f"PX4 {ver[0]}.{ver[1]} is sealed without the flag")
for ver in ((1,13),(1,18),(2,0)):
    d,p,rc,out=seal(f"v{ver[0]}{ver[1]}",with_ver(*ver))
    wrote=os.path.exists(d+"/out/flight.sfr")
    show(f"T5 PX4 {ver[0]}.{ver[1]} WITHOUT --allow-untested-version",["sfr","seal","flight.ulg","..."],rc,out,3,f"refused: {rc==4 and not wrote}; record written: {wrote}"); expect(rc==4 and not wrote, f"PX4 {ver[0]}.{ver[1]} is refused without the flag, nothing written")
    d,p,rc,out=seal(f"v{ver[0]}{ver[1]}f",with_ver(*ver),["--allow-untested-version"])
    rec=d+"/out/flight.sfr"; wrote=os.path.exists(rec)
    inrec=wrote and '"allow_untested_version":true' in open(rec).read()
    inrep=wrote and "Untested PX4 version" in open(rec+".md").read()
    rc2,out2=run([SFR,"verify",rec,"--pubkey",KEY+"/sfr.pub","--allow-evaluation-key","--ulog",p]) if wrote else (None,"")
    show(f"T5 PX4 {ver[0]}.{ver[1]} WITH --allow-untested-version",["sfr","seal","flight.ulg","...","--allow-untested-version"],rc,out,3,f"record written: {wrote}; allow_untested_version:true in the signed record: {inrec}; stated in the report: {inrep}; verify exit {rc2}"); expect(wrote and inrec and inrep and rc2==0, f"PX4 {ver[0]}.{ver[1]} with the flag: sealed, flag in the signed record and in the report, record verifies")
    if wrote: print("  report line:", [l for l in open(rec+".md").read().splitlines() if "ntested" in l][:1])
# a log with no readable version (pyulog sample)
d=f"{W}/nover"; os.makedirs(d)
cmd=[SFR,"seal","testdata/pyulog/sample.ulg","--rules","examples/rules.default.toml","--baseline","testdata/baselines/pyulog_sample.params","--key",KEY+"/sfr.key","--evaluation-only","--out",d]
rc,out=run(cmd); show("T5 log with no readable PX4 version (pyulog sample) WITHOUT the flag",["sfr","seal","testdata/pyulog/sample.ulg","..."],rc,out,3,f"refused: {rc==4}"); expect(rc==4, "a log with no readable version is refused without the flag")
# malformed and damaged inputs
random.seed(7)
vt=src
cases={
 "empty file": b"",
 "random bytes (4 KiB)": bytes(random.randrange(256) for _ in range(4096)),
 "text file": b"this is not a flight log\n"*40,
 "ULog magic only": b"ULog\x01\x12\x35\x01"+b"\x00"*8,
 "corrupted tail: cut mid-message": vt[:181699+10],
 "corrupted tail: last 100 bytes zeroed": vt[:-100]+b"\x00"*100,
 "corrupted tail: garbage appended": vt+bytes(random.randrange(256) for _ in range(300)),
 "corrupted middle: 64 bytes of 0xFF in the data section": vt[:200000]+b"\xff"*64+vt[200064:],
}
# The cases that end in the middle of a record, and the offset of that record.
ENDS_MID_RECORD={"corrupted tail: cut mid-message": 181699, "corrupted tail: garbage appended": len(vt)}
def mavlink_tlog():
    # .tlog: 8-byte big-endian microsecond timestamp, then a MAVLink 2 frame (HEARTBEAT, id 0), repeated
    pay=struct.pack("<IBBBBB",0,2,3,81,4,3)
    hdr=bytes([0xFD,len(pay),0,0,0,1,1])+(0).to_bytes(3,"little")
    frame=hdr+pay+b"\x00\x00"
    return b"".join(struct.pack(">Q",1_700_000_000_000_000+i*1_000_000)+frame for i in range(50))
def ardupilot_bin():
    # DataFlash .bin: 0xA3 0x95 <type> records; FMT (type 128, length 89) describes FMT itself
    fmt=bytes([0xA3,0x95,128,128,89])+b"FMT\0"+b"BBnNZ".ljust(16,b"\0")+b"Type,Length,Name,Format,Columns".ljust(64,b"\0")
    return fmt*20
cases["MAVLink .tlog (synthetic: 50 HEARTBEAT frames with timestamps)"]=mavlink_tlog()
cases["ArduPilot DataFlash .bin (synthetic: FMT records)"]=ardupilot_bin()
for name,data in cases.items():
    tag="".join(c if c.isalnum() else "_" for c in name)[:40]
    d=f"{W}/m_{tag}"; os.makedirs(d,exist_ok=True); p=d+"/in.ulg" if "tlog" not in name and ".bin" not in name else d+("/in.tlog" if "tlog" in name else "/in.bin"); open(p,"wb").write(data)
    cmd=[SFR,"seal",p,"--rules","examples/rules.default.toml","--baseline","testdata/baselines/v1.17.0_vtol_transition.params","--key",KEY+"/sfr.key","--evaluation-only","--out",d+"/out"]
    rc,out=run(cmd)
    wrote=os.path.exists(d+"/out") and bool(os.listdir(d+"/out"))
    crash = rc not in (0,1,2,3,4)
    verdict = "CRASH" if crash else ("clear refusal, nothing written" if rc in (3,4) and not wrote else f"sealed (record written={wrote})")
    show(f"T5 {name}",["sfr","seal","<file>","..."],rc,out,3,verdict)
    if "corrupted tail: last 100" in name or "corrupted middle" in name:
        print("  OBSERVATION: sealed without a warning; the seal covers the bytes as they are (damage inside well-formed records is not detectable at seal time)")
    elif name in ENDS_MID_RECORD:
        # The ULog specification asks a parser to handle a log that ends in the middle of a message
        # and discard the unfinished one. Appended garbage whose first bytes declare a record longer
        # than the rest of the file reads the same way.
        offset=ENDS_MID_RECORD[name]; trailing=len(data)-offset
        line=f"log ended mid-record at byte {offset}; {trailing} trailing bytes not parsed"
        recs=[f for f in os.listdir(d+"/out") if f.endswith(".sfr")] if wrote else []
        r=open(d+"/out/"+recs[0]).read() if recs else ""
        stated=f'"truncated":{{"offset":"{offset}","trailing_bytes":"{trailing}"}}' in r and '"schema_version":5' in r
        inrep=bool(recs) and line in open(d+"/out/"+recs[0]+".md").read()
        rc2,out2=run([SFR,"verify",d+"/out/"+recs[0],"--pubkey",KEY+"/sfr.pub","--allow-evaluation-key","--ulog",p]) if recs else (None,"")
        print(f"  => {line}: in the signed record {stated}; in the report {inrep}; verify --ulog exit {rc2}")
        expect(not crash and rc in (0,1,2) and stated and inrep and rc2==0 and "Integrity: VERIFIED (record and log)" in out2,
               f"{name}: sealed, the record and report state where it ends, and it verifies against the file")
    else:
        expect(not crash and rc in (3,4) and not wrote, f"{name}: clear refusal (exit {rc}), nothing written, no crash")

print("\nRESULT: PASS" if not FAILS else "\nRESULT: FAIL (%d)" % len(FAILS))
sys.exit(1 if FAILS else 0)
