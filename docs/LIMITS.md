# Input limits

`sfr` reads files someone else may have written: a log, a rules file, a baseline, a record. Each is bounded by the limits below, except the log's total size. SPEC B1.4 is the normative table; this page gives the reason for each limit, where it is enforced, and how it is tested.

## How a limit is reported

An input over a limit is refused, never truncated. A message for a count or a size names the limit and the SPEC section:

```text
sfr: log flight.ulg: the number of events exceeds the input limit of 100000 events (SPEC B1.4)
sfr: rules file rules.toml: line 3: `required_topics` exceeds the input limit of 256 entries (SPEC B1.4)
```

A message for a name, version or length rule ends with a parenthesis that states the rule and cites SPEC B1.4, for example `unsupported ULog file format version 2 (versions 0 and 1 are read; SPEC B1.4)`. `seal` names the byte offset (log) or line (rules file, baseline) where it met the limit. It names only the file for two counts (parameters at log start, events), the file sizes and TOML dotted-key depth. `verify` reports a limit in the record or in the `--ulog` log as its first mismatch (`FAILED: ...`); a public key over its limit exits 4.

| Command | Input | Exit code |
|---|---|---|
| `seal` | log, rules file, baseline; a log whose record would be over the record limit (`--dry-run` writes no record and does not apply that limit) | 3 |
| `seal` | key file; a rules file with more than 64 sealed topics (a usage error) | 4 |
| `verify` | public key | 4 |
| `verify` | record, or the log given with `--ulog` | 1 (verification failed) |

## The limits

| Limit | Value | Why | Enforced in |
|---|---|---|---|
| ULog file format version | 0 or 1 | Later versions may change the layout. | `ulog.rs` `read` |
| Format nesting | 8 levels below a subscribed format | Bounds the recursion of flattening. | `ulog.rs` `MAX_NESTING` |
| One flattened format | 65,535 bytes, 65,535 fields | A record's length field is 16 bits. Every field is at least one byte, so the byte limit is reached first. | `ulog.rs` `MAX_LAYOUT_SIZE` |
| Array length | 1 to 65,535 | The same 16-bit bound; a zero-length array has no meaning. | `ulog.rs` `parse_type` |
| Field definitions across all formats | 1,000,000 (a format with no fields counts as one) | Every definition is kept for the whole read. | `ulog.rs` `MAX_TOTAL_FIELDS` |
| Format name, field name, field type name | 255 bytes | Bounds the text each definition holds. | `ulog.rs` `parse_format` |
| Subscriptions | 4,096 | Far above any golden log. | `ulog.rs` `MAX_SUBSCRIPTIONS` |
| Flattened fields across all subscriptions | 1,000,000, counted per subscription | Bounds the work per subscription. Subscriptions of one format share its layout, so memory does not grow with this count. | `ulog.rs` `MAX_TOTAL_FIELDS` |
| Flattened field names, summed once per distinct subscribed format | 16 MiB | Bounds the text the shared layouts hold. A format redefined by a later format record is a distinct format. | `ulog.rs` `MAX_FLATTENED_NAME_BYTES` |
| Flattened field name (with nested prefixes and `[i]` index), subscription name | 255 bytes | Bounds the text kept per field and subscription. | `ulog.rs` `MAX_NAME_LEN` |
| Parameter name | 1 to 16 letters, digits, `_` | The PX4 rule, for the log and the baseline. | `params.rs` `valid_param_name` |
| Parameters at log start; baseline parameters | 65,536 | Bounds the parameter table. | `ingest.rs` with `params.rs` `MAX_PARAMS` |
| Events | 100,000 | A log where a failsafe toggles on every row could otherwise exhaust memory. Well above the 10,000 events at which SPEC B1.10 measures verify. | `events.rs` `MAX_EVENTS` |
| Rules file, baseline, key file, public key | 16 MiB each | Stops `sfr` reading an unbounded file into memory. | `sfr/src/main.rs` `MAX_TEXT_BYTES` |
| `required_topics.topics`, `parameters.ignore`, `watched_parameters.names`, `payload_commands.ids`, `authorized_sources.sources` | 256 entries each | Bounds the work per log. | `rules.rs` `MAX_LIST_ENTRIES` |
| `sealed_topics.topics` | 64 entries; more is a usage error, exit 4 | Each sealed topic instance keeps a running digest while the log streams. | `rules.rs` `MAX_SEALED_TOPICS` |
| Watched parameter name | 1 to 64 letters, digits, `_` | A parameter name pattern without `*`. | `rules.rs` `valid_param_name` |
| Payload command id; source system id; source component id | 0 to 4,294,967,295; 0 to 255; 0 to 65,535 | 32, 8 and 16 bits in PX4 v1.17. | `rules.rs` `parse_payload_commands`, `parse_authorized_sources` |
| Topic name | 1 to 64 lowercase letters, digits, `_` | The uORB rule. | `rules.rs` `valid_topic` |
| Parameter name pattern | 1 to 64 characters, at most 8 `*` | Matching cost grows with the number of `*`. | `params.rs` `MAX_PATTERN_STARS` |
| TOML nesting and dotted keys | 80 levels | The `toml` parser's own limit, reported as an input limit. Nested arrays and inline tables get a line number; a dotted key or table header names only the file. | `rules.rs` `TOML_MAX_DEPTH` |
| Record | 512 MiB | `seal` refuses to write a larger record and `verify` refuses to read one (it reads at most one byte past the limit), so `seal` never writes a record `verify` would refuse. | `verify.rs` `check_record_size` |
| Record JSON nesting | 64 nested arrays and objects | Bounds the parser's recursion. | `json.rs` `MAX_DEPTH` |

## What has no limit

The log has no size limit. It is read once, as a stream, and every byte is hashed. The reader keeps format definitions, subscriptions, one flattened layout per distinct subscribed format, and the parameters at log start, each bounded by the limits above; and the data records the events and rules use (`vehicle_status`, `failsafe_flags`, commands and acks, GPS, battery, estimator, estimator selector, IMU and sensor selection rows, warning messages with their text, dropouts, and data-section parameter records). It drops every other record after hashing it. The number of kept data records has no limit, so memory grows with them: a log made mostly of them needs memory in proportion to its size.

## The sandbox's limit

The browser engine bundle ([SANDBOX.md](SANDBOX.md)) has one limit of its own, which is not a SPEC B1.4 limit and does not apply to the command line:

| Limit | Value | Why | Enforced in | Tested by |
|---|---|---|---|---|
| One log or record in the browser engine | 100 MiB (104,857,600 bytes) | The browser decides how much memory a tab may use, and a tab that runs out stops without a message. The engine streams the log, but the browser also holds the chosen files and the demo's sample. | `crates/sfr-wasm` `MAX_SANDBOX_FILE_BYTES`: refused by the size the browser reports, before a byte is read, and again by the bytes read (one byte past the limit) | `crates/sfr-wasm` `a_log_over_the_sandbox_limit_is_refused_by_size_and_by_length`; `tests/browser/sandbox.test.mjs` checks `limit` (a file one byte over, in each browser) and `memory` (Chromium: the largest log under the limit is sealed and verified, and each browser process's peak memory goes in the CI job summary) |

A file over it is refused with exit 4 and this message, never truncated:

```text
log flight.ulg: 104857601 bytes is over the sandbox's limit of 104857600 bytes (100 MiB) for one file; use the sfr command line, which has no limit on the log (docs/LIMITS.md)
```

The rules file, baseline, key file and public key keep the command line's 16 MiB limit (`MAX_TEXT_BYTES`) in the sandbox.

## One limit that truncates

R4, R5, R6, R7, X2 and X3 list at most 1,000 `detail` lines (`evaluate.rs` `MAX_DETAIL_LINES`). Past that, the detail ends with one line saying where the rest are counted: `and N more; the events list every one` for R4, R5, R6, R7 and X2 (their cases are events), and `and N more; the count above includes every sample` for X3. This limits output, not input: it is not an error and the rule's status is unchanged. R3 is not capped: SPEC B1.6 has it list every differing parameter, so at most the two parameter limits together.

## Testing

Every limit above has a unit test next to the code that enforces it (`ulog.rs`, `ingest.rs`, `events.rs`, `rules.rs`, `params.rs`, `json.rs`, `verify.rs` and `evaluate.rs`), and `crates/sfr/tests/seal_dry_run.rs` `oversize_text_inputs_are_refused_and_name_the_limit` covers the file and record sizes through the command line. Each test crosses the limit by one and checks the message, and also checks that an input exactly at the limit is accepted. Search the source for the constant in the last column to find them.

Three cases are not tested at the limit: the baseline file size (same read path as the rules file); the record size limit in `seal` (it needs a log large enough to give a record over 512 MiB; `seal` and `verify` share `check_record_size`, which is tested); and 65,535 fields per format (the byte limit is always reached first). Subscriptions of one format share one layout, which `ulog.rs` `subscriptions_of_one_format_share_one_layout` and `ingest.rs` `failsafe_subscriptions_share_one_schema` check on `fuzz/seeds/ulog_ingest/subscription_amplification.ulg`.

The fuzz targets (`fuzz/`) run with `-max_len=1048576`, `-rss_limit_mb=2048` and `-timeout=10`, so an input of up to 1 MiB that makes `sfr` use more than 2,048 MB or run longer than 10 s fails the run. The seed `subscription_amplification.ulg` (written by `scripts/testdata/make_amplification_seed.py`) did that before formats were flattened once and shared; it runs in every CI fuzz job. The fuzz targets do not exercise the memory growth of large logs described above.
