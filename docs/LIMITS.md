# Input limits

`sfr` reads files that someone else may have written: a log, a rules file, a baseline, a record. Each of them, except the log's total size, is bounded by the limits below. SPEC B1.4 is the normative table; this page gives the reason for each limit, where it is enforced, and how it is tested.

## How a limit is reported

An input over a limit is refused, never truncated. A message for a count or a size names the limit and the SPEC section:

```
sfr: log flight.ulg: the number of events exceeds the input limit of 100000 events (SPEC B1.4)
sfr: rules file rules.toml: line 3: `required_topics` exceeds the input limit of 256 entries (SPEC B1.4)
```

A message for a name, version, or length rule ends with a parenthesis that states the rule and cites SPEC B1.4, for example `unsupported ULog file format version 2 (versions 0 and 1 are read; SPEC B1.4)` or `array length in `uint8_t[65536]` is not allowed (1 to 65535 elements; SPEC B1.4)`. `seal` names the byte offset (log) or line (rules file, baseline) where it met the limit, except for exactly these, which name the file only: three counts (parameters at log start, `failsafe_flags` flag fields, events), the file sizes, and TOML dotted-key depth. The other log counts (field definitions, subscriptions, flattened fields, flattened name bytes) name the offset of the record that crossed them. `verify` reports a limit in the record or in the `--ulog` log as its first mismatch, `FAILED: ...`, and its `--json` output also names the record; a public key over its limit exits 4.

| Command | Input | Exit code |
|---|---|---|
| `seal` | log, rules file, baseline; a log whose record would be over the record limit (`--dry-run` writes no record and does not apply that limit) | 3 |
| `seal` | key file; a rules file with more than 64 sealed topics (a usage error, Change Order 01) | 4 |
| `verify` | public key | 4 |
| `verify` | record, or the log given with `--ulog` | 1 (verification failed) |

## The limits

| Limit | Value | Why | Enforced in |
|---|---|---|---|
| ULog file format version | 0 or 1 | Later versions may change the layout; `sfr` refuses rather than guesses. | `ulog.rs` `read` |
| Format nesting | 8 levels of nested types below a subscribed format | Nested types are flattened recursively; the cap bounds the recursion. | `ulog.rs` `MAX_NESTING` |
| One flattened format | 65,535 bytes, 65,535 fields | A record's length field is 16 bits, so no data record can be longer; its payload after the two-byte message id is two bytes shorter still. Every field is at least one byte, so the byte limit is reached first. | `ulog.rs` `MAX_LAYOUT_SIZE` |
| Array length | 1 to 65,535 | The same 16-bit bound; a zero-length array has no meaning. | `ulog.rs` `parse_type` |
| Field definitions across all formats | 1,000,000 (a format with no fields counts as one) | Every format definition is kept for the whole read; this bounds how many. | `ulog.rs` `MAX_TOTAL_FIELDS` |
| Format name, field name, field type name | 255 bytes | Bounds the text each kept definition holds. | `ulog.rs` `parse_format` |
| Subscriptions | 4,096 | Each subscription keeps a small entry; the cap is far above what any golden log has. | `ulog.rs` `MAX_SUBSCRIPTIONS` |
| Flattened fields across all subscriptions | 1,000,000, counted per subscription | Bounds the work done per subscription. Each format is flattened once and its subscriptions share the layout, so memory does not grow with this count. | `ulog.rs` `MAX_TOTAL_FIELDS` |
| Flattened field names, summed once per distinct subscribed format | 16 MiB | Bounds the text the shared layouts hold. A format redefined by a later format record is a distinct format. The cap is far above what any golden log uses. | `ulog.rs` `MAX_FLATTENED_NAME_BYTES` |
| Flattened field name (with nested prefixes and `[i]` index), subscription name | 255 bytes | Bounds the text kept per flattened field and per subscription. | `ulog.rs` `MAX_NAME_LEN` |
| Parameter name | 1 to 16 letters, digits, `_` | The PX4 parameter name rule, for the log and the baseline. | `params.rs` `valid_param_name` |
| Parameters at log start | 65,536 | Bounds the parameter table. | `ingest.rs` with `params.rs` `MAX_PARAMS` |
| `failsafe_flags` flag fields | 256 | Each failsafe edge gives one event per named flag and R4 lists the flags, so the count bounds the events per edge, each R4 line, and each kept `failsafe_flags` row. | `ingest.rs` `MAX_FAILSAFE_FLAGS` |
| Events | 100,000 | A log built so that a failsafe toggles on every row could otherwise build a timeline and a record that exhaust memory. It is well above the 10,000 events at which SPEC B1.10 measures standalone verify. | `events.rs` `MAX_EVENTS` |
| Rules file, baseline, key file, public key | 16 MiB each | These are small text files; the cap stops `sfr` reading an unbounded file into memory. | `sfr/src/main.rs` `MAX_TEXT_BYTES` |
| `required_topics.topics`, `parameters.ignore`, `watched_parameters.names`, `payload_commands.ids`, `authorized_sources.sources` | 256 entries each | Bounds the work done per log. | `rules.rs` `MAX_LIST_ENTRIES` |
| `sealed_topics.topics` | 64 entries; more is a usage error, exit 4 | Each sealed topic instance keeps one running digest while the log streams; Change Order 01 sets the cap and the exit code. | `rules.rs` `MAX_SEALED_TOPICS` |
| Watched parameter name | 1 to 64 letters, digits, `_` | The same bound as a parameter name pattern, without `*`. | `rules.rs` `valid_param_name` |
| Payload command id; source system id; source component id | 0 to 4,294,967,295; 0 to 255; 0 to 65,535 | `vehicle_command.command` is 32 bits; `source_system` is 8 bits; `source_component` is 16 bits in PX4 v1.17. | `rules.rs` `parse_payload_commands`, `parse_authorized_sources` |
| Topic name | 1 to 64 lowercase letters, digits, `_` | The uORB topic name rule. | `rules.rs` `valid_topic` |
| Parameter name pattern | 1 to 64 characters, at most 8 `*` | Wildcard matching cost grows with the number of `*`; the cap keeps it small. | `params.rs` `MAX_PATTERN_STARS` |
| TOML nesting and dotted keys | 80 levels | The `toml` parser's own limit; `sfr` reports it as an input limit. The parser gives a line for nested arrays and inline tables but not for a dotted key or table header, which name the file only. | `rules.rs` `TOML_MAX_DEPTH` |
| Baseline parameters | 65,536 | Same as parameters at log start. | `params.rs` `MAX_PARAMS` |
| Record | 512 MiB | `seal` refuses to write a larger record and `verify` refuses to verify one (it reads at most one byte past the limit), so `seal` never writes a record `verify` would refuse. | `verify.rs` `check_record_size` |
| Record JSON nesting | 64 nested arrays and objects | Bounds the parser's recursion. | `json.rs` `MAX_DEPTH` |

## What has no limit

The log has no size limit. It is read once, as a stream, and every byte is hashed. The reader keeps:

- format definitions, subscriptions, one flattened layout per distinct subscribed format (shared by its subscriptions), and the parameters at log start, each bounded in count and size by the limits above;
- the data records the events and rules use: `vehicle_status`, `failsafe_flags`, commands and acks, GPS, battery, estimator, estimator selector, IMU and sensor selection rows, warning messages with their text, dropouts, and data-section parameter records.

It drops every other record after hashing it. The number of kept data records has no limit, so memory grows with them: a log made mostly of them needs memory in proportion to its size. The definitions in the first list cost at most what their limits allow, which for format definitions near their limits is still large; a log made mostly of other data records needs little.

## One limit that truncates

R4, R5, R6, X2, and X3 list at most 1,000 `detail` lines (`evaluate.rs` `MAX_DETAIL_LINES`). Past that, the detail ends with one line that says where the rest are counted: `and N more; the events list every one` for R4, R5, R6, and X2, whose cases are all events (an R4 case is a FAILSAFE_SET or QUADCHUTE event, or the ARM event when the failsafe was already set at ARM), and `and N more; the count above includes every sample` for X3, whose cases are estimator samples. This limits output, not input: it is not an error, and the rule's status is unchanged. R3 is not capped: SPEC B1.6 has it list every differing parameter, so at most the two parameter limits together.

## Testing

Each test below crosses the limit by one and checks the message, unless the row says otherwise; "and at" means the test also checks that an input exactly at the limit is accepted.

| Limit | Test |
|---|---|
| ULog version | `ulog.rs` `version_parameter_name_and_array_length_limits_are_named` (2 refused; 0 and 1 accepted) |
| Log parameter name | same test, and at (16 and 17 characters) |
| Array length | same test, and at (65,535; 65,536 and 100000 refused); `names_in_format_definitions_are_capped` (leading zeros: `[000001]` and `[0065535]` accepted, `[00000]` and `[0065536]` refused with the message) |
| Format nesting | `ulog.rs` `nesting_and_name_limits_hold_exactly_at_the_limit`, and at (8 and 9) |
| Flattened field name | same test, and at, for an array element and a nested field (a 256-byte plain field is refused earlier, as a field name); `long_names_are_refused` (an array element of 256 bytes) |
| Subscription name | `long_names_are_refused` (256 refused); `nesting_and_name_limits_hold_exactly_at_the_limit` (255 accepted) |
| One flattened format | `ulog.rs` `format_size_and_definition_limits_are_named`, and at (65,535 and 65,536 bytes) |
| Field definitions across all formats | same test, and at (1,000,000; the 1,000,001st is a format with no fields) |
| Format name, field name, field type name | `ulog.rs` `names_in_format_definitions_are_capped`, and at (255 and 256 bytes each) |
| Subscriptions | `ulog.rs` `subscription_count_and_flattened_name_limits_are_exact`, and at (4,096 and 4,097) |
| Flattened fields across all subscriptions | `ulog.rs` `total_flattened_fields_are_capped`, and at (1,000,000 and 1,000,001) |
| Flattened field names per distinct format | `ulog.rs` `subscription_count_and_flattened_name_limits_are_exact`, and at (16,777,216 and 16,777,217 bytes across 275 formats; one format subscribed 300 times is counted once) |
| Shared layouts (not a limit; the memory fix the two rows above rely on) | `ulog.rs` `subscriptions_of_one_format_share_one_layout` and `ingest.rs` `failsafe_subscriptions_share_one_schema`, on `fuzz/seeds/ulog_ingest/subscription_amplification.ulg` (3,891 subscriptions of one format share one layout and one flag schema) |
| Parameters at log start | `ingest.rs` `too_many_parameters_at_log_start_are_refused` (65,537 refused) and `exactly_the_parameter_and_flag_limits_are_accepted` (65,536 accepted, with a data record) |
| `failsafe_flags` flag fields | `ingest.rs` `a_failsafe_flags_format_with_too_many_flags_is_refused` (257 refused) and `exactly_the_parameter_and_flag_limits_are_accepted` (256 accepted, with a data record) |
| Events | `events.rs` `a_timeline_of_exactly_the_event_cap_is_accepted`, and at (100,000 and 100,001); `a_timeline_over_the_event_cap_is_refused` (a failsafe toggling on 8,000 rows with 256 flags: far over, not by one) |
| `required_topics.topics`, `parameters.ignore`, `*` per pattern | `rules.rs` `list_and_pattern_limits_are_enforced_and_named`, and at (256 and 257 entries; 8 and 9 `*`) |
| Topic name | same test (65 bytes refused) |
| `sealed_topics.topics` | `rules.rs` `change_order_01_sections_reject_bad_input`, and at (64 accepted; 65 refused as a usage error) |
| Watched parameter name, payload command id, MAVLink ids, the new sections' other rules | same test (a bad name, an id over 32 bits, a system id of 256, duplicates, an empty source list, a watched name the ignore list matches) |
| Parameter name pattern length | `rules.rs` `pattern_length_and_toml_depth_limits_are_named`, and at (64 and 65) |
| TOML nesting and dotted keys | same test (81 nested arrays and a 100-part dotted key refused) |
| Baseline parameters | `params.rs` `baseline_parameter_limit_is_enforced_and_named`, and at (65,536 and 65,537) |
| Baseline parameter name | `params.rs` `baseline_parameter_names_follow_the_px4_rule`, and at (16 and 17) |
| Rules file size | `crates/sfr/tests/seal_dry_run.rs` `oversize_text_inputs_are_refused_and_name_the_limit`, and at (16 MiB accepted, exit 0; one byte more, exit 3) |
| Key file and public key size | same test (one byte over 16 MiB: `seal --key` and `verify --pubkey` exit 4) |
| Record size, `verify` | same test (sparse files 1 and 2 bytes over 512 MiB: exit 1, with and without `--json`); `verify.rs` `the_record_size_limit_is_exact_and_named`, and at |
| Record JSON nesting | `json.rs` `parse_round_trips_canonical_text_and_rejects_the_rest`, and at (64 and 65, for both the parser and the canonical scan) |
| Detail lines (a cap on output, not a refusal) | `evaluate.rs` `r4_lists_at_most_the_detail_cap_and_counts_the_rest` (1,500 cases: 1,000 lines and `and 500 more`) |

Not crossed by a test: the baseline file size (it uses the same read path as the rules file); the record size limit in `seal` (crossing it needs a log large enough to give a record over 512 MiB; `seal` and `verify` share `check_record_size`, which is tested); and the 65,535 fields per format (the byte limit is always reached first).

The fuzz targets (`fuzz/`) run with `-max_len=1048576`, `-rss_limit_mb=2048`, and `-timeout=10`, so an input of up to 1 MiB that makes `sfr` use more than 2,048 MB, or run longer than 10 s, fails the run. The seed `subscription_amplification.ulg` (written by `scripts/testdata/make_amplification_seed.py`) did that before formats were flattened once and shared; it runs in every CI fuzz job. The fuzz targets do not exercise the memory growth of large logs described above.
