# Long functions

Functions of shipped code over the long-function limit, and the functions with the most branches. They are candidates for simplification, which the plan allows only after the chunk that holds them is pinned by tests (`docs/review/PLAN.txt`, refactoring rule). Rendered by `scripts/review/ledger.py render` from `docs/review/ledger.json`; the branch count is the one `tools/review_metrics` defines (each `if`, match arm, match guard, `while`, `for`, `&&`, `||`, `?` and `let ... else`).

<!-- BEGIN long-functions: scripts/review/ledger.py render -->
Functions over 100 code lines: 22.

| Function | File | Lines | Code lines | Branches | Chunk |
|---|---|---|---|---|---|
| `verify_cmd` | `sfr/src/main.rs` | 1059-1622 | 531 | 100 | C4.7 |
| `render` | `sfr-core/src/report.rs` | 364-776 | 387 | 95 | C7.2 |
| `standalone` | `sfr-core/src/verify.rs` | 590-997 | 373 | 107 | C4.3 |
| `read` | `sfr-core/src/ulog.rs` | 961-1330 | 351 | 102 | C1.5 |
| `seal_cmd` | `sfr/src/main.rs` | 614-973 | 340 | 73 | C8.8 |
| `parse_rules` | `sfr-core/src/rules.rs` | 397-658 | 252 | 64 | C6.2 |
| `r4` | `sfr-core/src/evaluate.rs` | 764-976 | 201 | 37 | C2.3 |
| `impl Visitor for Collector<'_>::data` | `sfr-core/src/ingest.rs` | 1007-1194 | 184 | 26 | C1.9 |
| `impl Collector<'_>::finish` | `sfr-core/src/ingest.rs` | 1222-1396 | 164 | 16 | C1.9 |
| `check_chain` | `sfr/src/certs.rs` | 966-1130 | 154 | 29 | C3.4 |
| `instance_events` | `sfr-core/src/events.rs` | 515-670 | 152 | 27 | C2.8 |
| `compare` | `sfr-core/src/verify.rs` | 1066-1210 | 140 | 38 | C4.4 |
| `parse_crl` | `sfr/src/certs.rs` | 515-660 | 137 | 55 | C3.2 |
| `r3` | `sfr-core/src/evaluate.rs` | 330-465 | 134 | 22 | C2.2 |
| `seal` | `sfr-core/src/seal.rs` | 439-568 | 127 | 6 | C5.7 |
| `impl Visitor for Collector<'_>::subscription` | `sfr-core/src/ingest.rs` | 888-1005 | 115 | 17 | C1.8 |
| `r7` | `sfr-core/src/evaluate.rs` | 1224-1335 | 111 | 11 | C2.5 |
| `build` | `sfr-core/src/events.rs` | 746-854 | 105 | 12 | C2.9 |
| `x4` | `sfr-core/src/evaluate.rs` | 1524-1630 | 103 | 14 | C2.6 |
| `keygen` | `sfr/src/main.rs` | 267-369 | 102 | 19 | C8.6 |
| `r6` | `sfr-core/src/evaluate.rs` | 1073-1175 | 101 | 16 | C2.4 |
| `tpm_keygen` | `sfr/src/hardware.rs` | 340-446 | 101 | 20 | C8.3 |
<!-- END long-functions -->

## Most branches

<!-- BEGIN most-branches: scripts/review/ledger.py render -->
| Function | File | Lines | Code lines | Branches | Chunk |
|---|---|---|---|---|---|
| `standalone` | `sfr-core/src/verify.rs` | 590-997 | 373 | 107 | C4.3 |
| `read` | `sfr-core/src/ulog.rs` | 961-1330 | 351 | 102 | C1.5 |
| `verify_cmd` | `sfr/src/main.rs` | 1059-1622 | 531 | 100 | C4.7 |
| `render` | `sfr-core/src/report.rs` | 364-776 | 387 | 95 | C7.2 |
| `seal_cmd` | `sfr/src/main.rs` | 614-973 | 340 | 73 | C8.8 |
| `parse_rules` | `sfr-core/src/rules.rs` | 397-658 | 252 | 64 | C6.2 |
| `parse_crl` | `sfr/src/certs.rs` | 515-660 | 137 | 55 | C3.2 |
| `impl Pkcs11Uri::parse` | `sfr-core/src/pkcs11_uri.rs` | 94-189 | 95 | 41 | C6.5 |
| `compare` | `sfr-core/src/verify.rs` | 1066-1210 | 140 | 38 | C4.4 |
| `r4` | `sfr-core/src/evaluate.rs` | 764-976 | 201 | 37 | C2.3 |
| `parse_seal_time_seconds` | `sfr-core/src/seal.rs` | 616-690 | 75 | 36 | C5.8 |
| `why` | `sfr/src/certs.rs` | 773-862 | 90 | 34 | C3.3 |
| `check_chain` | `sfr/src/certs.rs` | 966-1130 | 154 | 29 | C3.4 |
| `impl Parser<'_>::string` | `sfr-core/src/json.rs` | 398-466 | 69 | 28 | C5.2 |
| `instance_events` | `sfr-core/src/events.rs` | 515-670 | 152 | 27 | C2.8 |
| `impl Visitor for Collector<'_>::data` | `sfr-core/src/ingest.rs` | 1007-1194 | 184 | 26 | C1.9 |
| `impl Parser<'_>::value` | `sfr-core/src/json.rs` | 277-347 | 71 | 25 | C5.1 |
| `impl Scanner<'_>::object` | `sfr-core/src/json.rs` | 725-789 | 64 | 25 | C5.3 |
| `schema_5_members` | `sfr-core/src/verify.rs` | 399-476 | 78 | 23 | C4.2 |
| `leaves` | `sfr-core/src/seal.rs` | 255-308 | 54 | 22 | C5.6 |
<!-- END most-branches -->

