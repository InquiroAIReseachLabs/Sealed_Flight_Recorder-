# golden_logs.sh: the golden log list, sourced by scripts/testdata/regenerate.sh and
# scripts/benchmark.sh. Run from the repository root (or the root of the benchmark kit).

# Prints one "name log-path" line per golden log: the pyulog sample, every SITL log
# (<version>_<file stem>), every synthetic log (synthetic_<file stem>).
golden_logs() {
  echo "pyulog_sample testdata/pyulog/sample.ulg"
  for f in testdata/sitl/*/*.ulg; do
    v=$(basename "$(dirname "$f")")
    echo "${v}_$(basename "$f" .ulg) $f"
  done
  for f in testdata/synthetic/*.ulg; do
    echo "synthetic_$(basename "$f" .ulg) $f"
  done
}

# The rules file a golden log is sealed with: testdata/rules/<name>.toml when it exists (the
# default rules plus what that log needs, such as [sealed_topics]), else the default.
golden_rules_for() {
  if [ -f "testdata/rules/$1.toml" ]; then echo "testdata/rules/$1.toml"; else echo examples/rules.default.toml; fi
}
