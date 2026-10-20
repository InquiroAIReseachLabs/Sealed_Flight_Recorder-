#!/usr/bin/env python3
"""T8 Rules R1 to R7: one sentence each, and a fixture that makes each one fail. Needs the key T2 made."""
import os, re, shutil, struct, subprocess, sys
R=os.environ["A_REPO"]; SFR=os.environ["A_SFR"]; AW=os.environ["A_WORK"]; W=AW+"/t08"; shutil.rmtree(W, ignore_errors=True); os.makedirs(W)
KEY=AW+"/t02/key"
def run(a):
    p=subprocess.run(a,cwd=R,capture_output=True,text=True); return p.returncode,p.stdout+p.stderr
def seal(tag, log, rules, baseline, extra=()):
    out=f"{W}/{tag}"
    rc,o=run([SFR,"seal",log,"--rules",rules,"--baseline",baseline,"--key",KEY+"/sfr.key","--evaluation-only","--seal-time","2026-10-18T15:00:00Z","--out",out,*extra])
    return rc,o
def line(o,r): 
    m=[l for l in o.splitlines() if l.startswith(r+" ")]; 
    return (m[0] if m else "(no line)")[:150]
VT="testdata/sitl/v1.17.0/vtol_transition.ulg"; VB="testdata/baselines/v1.17.0_vtol_transition.params"; DR="examples/rules.default.toml"
print("""Rules, one sentence each (from docs/RULES.md and SPEC B1.5):
 R1 Every topic the rules file requires, and the core topics and fields the rules read, must have data in the log.
 R2 The firmware version (and git hash, when the baseline gives one) in the log must equal the baseline's.
 R3 The parameters at log start must equal the baseline's, name for name and value for value.
 R4 The vehicle must never be in a failsafe, and a VTOL must never quadchute, between arming and disarming.
 R5 Every arm must be followed by a disarm, and the log must not end armed.
 R6 Every VTOL transition that starts must end, and none may be aborted.
 R7 (optional) Every command in the log must come from a MAVLink system and component listed in the rules file.
""")
results=[]
def check(rid, desc, tag, log, rules, baseline, extra=()):
    rc,o=seal(tag,log,rules,baseline,extra)
    l=line(o,rid); ok=bool(re.match(rf"{rid}\s+FAIL",l))
    print(f"[{rid}] fixture: {desc}\n  command: sfr seal {log} --rules {rules} --baseline {baseline} ...   exit {rc}\n  {l}")
    for d in [x for x in o.splitlines() if x.startswith("      ") or x.startswith("              -")][:2]: print("   "+d.strip()[:150])
    print("  => rule FAILS as required" if ok else "  => PROBLEM: rule did not fail"); results.append((rid,ok))
# a clean control
rc,o=seal("control",VT,DR,VB); print("[control] golden vtol_transition: exit",rc,"; R-lines:", " | ".join(line(o,f"R{i}").split()[0]+" "+line(o,f"R{i}").split()[1] for i in range(1,8)))
# R1
open(W+"/r1.toml","w").write(open(f"{R}/{DR}").read().replace('topics = ["vehicle_status", "failsafe_flags"]','topics = ["vehicle_status", "failsafe_flags", "no_such_topic"]',1))
print("rules file edit check:", "no_such_topic" in open(W+"/r1.toml").read())
check("R1","default rules plus a required topic the log does not have (no_such_topic)","r1",VT,W+"/r1.toml",VB)
# R2
b=open(f"{R}/{VB}").read(); b2=re.sub(r"# Firmware:.*","# Firmware: 1.16.2",b); open(W+"/r2.params","w").write(b2)
check("R2","baseline says firmware 1.16.2, the log is 1.17.0","r2",VT,DR,W+"/r2.params")
# R3
b3=b.replace("MPC_XY_VEL_MAX\t8","MPC_XY_VEL_MAX\t9",1) if "MPC_XY_VEL_MAX\t8" in b else None
import itertools
if b3 is None:
    m=re.search(r"^(\d+\t\d+\tMPC_XY_VEL_MAX\t)([^\t\n]+)",b,re.M); print("param line:",m.group(0) if m else None)
    b3=b.replace(m.group(0), m.group(1)+"9.0",1)
open(W+"/r3.params","w").write(b3)
check("R3","baseline changes one parameter (MPC_XY_VEL_MAX) from the flown value","r3",VT,DR,W+"/r3.params")
# R4 golden
check("R4","golden log failsafe_gps_loss (GPS loss failsafe in flight)","r4","testdata/sitl/v1.17.0/failsafe_gps_loss.ulg",DR,"testdata/baselines/v1.17.0_failsafe_gps_loss.params")
# R5: cut the VTOL log at a message boundary while armed
src=open(f"{R}/{VT}","rb").read()
pos=16; msgs=[]
while pos+3<=len(src):
    size=struct.unpack("<H",src[pos:pos+2])[0]; msgs.append((pos,3+size,src[pos+2:pos+3])); pos+=3+size
dm=[m for m in msgs if m[2]==b"D"]
cut=None
for frac in (0.3,0.25,0.35,0.4,0.2):
    c=dm[int(len(dm)*frac)][0]; open(W+"/r5.ulg","wb").write(src[:c]); rc,o=seal("r5probe",W+"/r5.ulg",DR,VB)
    if re.match(r"R5\s+FAIL",line(o,"R5")): cut=c; break
    shutil.rmtree(W+"/r5probe",ignore_errors=True)
print("R5 fixture cut offset:",cut)
shutil.rmtree(W+"/r5probe",ignore_errors=True)
check("R5","the golden VTOL log cut at a message boundary while armed (the log ends armed)","r5",W+"/r5.ulg",DR,VB)
# R6 golden
check("R6","golden log vtol_transition_abort (a transition aborted)","r6","testdata/sitl/v1.17.0/vtol_transition_abort.ulg",DR,"testdata/baselines/v1.17.0_vtol_transition_abort.params")
# R7 golden + own rules
check("R7","golden log payload_two_sources with its rules file ([authorized_sources] lists one source)","r7","testdata/sitl/v1.17.0/payload_two_sources.ulg","testdata/rules/v1.17.0_payload_two_sources.toml","testdata/baselines/v1.17.0_payload_two_sources.params")
r7b=open(f"{R}/{DR}").read()+'\n[authorized_sources]\nsources = [{ system = 200, component = 200 }]\n'
open(W+"/r7b.toml","w").write(r7b)
check("R7","the golden VTOL log with default rules plus [authorized_sources] = system 200 component 200","r7b",VT,W+"/r7b.toml",VB)
bad=[r for r,ok in results if not ok]
print("\nRESULT: PASS" if not [r for r,ok in results if not ok] and len(results)==8 else "\nRESULT: FAIL")
print("SUMMARY:", {r:ok for r,ok in results}); print("rules with a failing fixture:", sorted({r for r,ok in results if ok}), "; problems:", bad)

sys.exit(0 if (not [r for r,ok in results if not ok] and len(results)==8) else 1)
