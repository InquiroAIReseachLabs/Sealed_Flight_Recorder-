#!/usr/bin/env bash
# T6 Offline: keygen, seal and verify inside an empty network namespace (unshare -n), with strace tracing every
# network system call. Needs unshare, strace and (as root, or with user namespaces) the right to make a namespace.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
R=$A_REPO; SFR=$A_SFR; W=$A_WORK/t06; rm -rf $W; mkdir -p $W; cd $R
echo "commit $(git rev-parse HEAD)"
echo "--- control: the network namespace is really empty"
unshare -n sh -c 'ip -o link 2>/dev/null || cat /proc/net/dev | tail -n +3; echo "route:"; cat /proc/net/route | wc -l; curl -sS -m 5 -o /dev/null https://static.rust-lang.org 2>&1 | head -1; echo "curl exit: $?"'
echo
echo "--- keygen, seal, verify (with --ulog) inside unshare -n, under strace -f tracing every network system call"
unshare -n strace -f -qq -e trace=%network -o $W/strace.txt sh -c "
  $SFR keygen --evaluation-only --out $W/key > /dev/null &&
  $SFR seal testdata/sitl/v1.17.0/vtol_transition.ulg --rules examples/rules.default.toml --baseline testdata/baselines/v1.17.0_vtol_transition.params --key $W/key/sfr.key --evaluation-only --out $W/out > $W/seal.txt; echo \"seal exit \$?\";
  $SFR verify $W/out/vtol_transition.sfr --pubkey $W/key/sfr.pub --allow-evaluation-key --ulog testdata/sitl/v1.17.0/vtol_transition.ulg | grep -E '^(Integrity|Rule checks)'; echo \"verify exit \${PIPESTATUS:-\$?}\""
echo
echo "network system calls traced (socket, connect, bind, send, recv, ...): $(grep -c -E '^[0-9]+ +[a-z_0-9]+\(' $W/strace.txt)  (lines that are only signal notices: $(grep -c -E 'SIG[A-Z]+ ' $W/strace.txt))"
echo
echo "--- positive control: the same strace command catches a network call (curl)"
strace -f -qq -e trace=%network -o $W/strace-control.txt curl -sS -m 3 -o /dev/null http://127.0.0.1:9 2>/dev/null; echo "control traced calls: $(grep -c -E 'socket|connect' $W/strace-control.txt)"; head -3 $W/strace-control.txt
echo
echo "--- the same, for every system call that opens a socket, over a standalone verify"
unshare -n strace -f -qq -e trace=socket,connect,bind,listen,accept,sendto,sendmsg,recvfrom,recvmsg -o $W/strace2.txt $SFR verify $W/out/vtol_transition.sfr --pubkey $W/key/sfr.pub --allow-evaluation-key; echo "exit $? ; traced: $(grep -c -E "^[0-9]+ +[a-z_0-9]+\(" $W/strace2.txt)"
n1=$(grep -c -E '^[0-9]+ +[a-z_0-9]+\(' $W/strace.txt); n2=$(grep -c -E "^[0-9]+ +[a-z_0-9]+\(" $W/strace2.txt)
check "no network system call during keygen, seal and verify --ulog" "$([ "$n1" -eq 0 ]; echo $?)"
check "no socket system call during a standalone verify" "$([ "$n2" -eq 0 ]; echo $?)"
check "the positive control (curl) was traced" "$([ "$(grep -c -E 'socket|connect' $W/strace-control.txt)" -gt 0 ]; echo $?)"
echo
echo "--- static check: network crates and std::net in the source (scripts/check_deny_list.sh)"
scripts/check_deny_list.sh 2>&1 | tail -4
check "the deny-list check passes (no networking crate, no std socket use)" "${PIPESTATUS[0]}"
finish
