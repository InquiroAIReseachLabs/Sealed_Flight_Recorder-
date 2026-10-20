#!/usr/bin/env bash
# T13 pyulog differential: sfr and the test-only pyulog oracle, both run now, on every golden log
# and every false-pass case (scripts/testdata/oracle_differential.py). SFR_ORACLE_PYTHON names a
# Python with the packages of scripts/testdata/requirements-dev.txt.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$A_REPO" || exit 1
py="${SFR_ORACLE_PYTHON:-python3}"
"$py" -I -c 'import pyulog, numpy; print("pyulog", pyulog.__version__ if hasattr(pyulog, "__version__") else "?", "numpy", numpy.__version__)'
check "a Python with pyulog ($py)" $?
"$py" -I scripts/testdata/oracle_differential.py "$A_SFR"
check "sfr and the oracle agree on every golden and false-pass log" $?
finish
