# Input limits

`sfr` reads files that an attacker may have written: a crafted log, a rules file, a baseline, a record. Every one of them is bounded so that no input can make `sfr` hang, exhaust memory, or run for an unbounded time. SPEC B1.4 is the normative table; this page gives the reason for each limit and where it is enforced.

## How a limit is reported

An input over a limit is refused, never silently truncated. The message names the file, the place (a byte offset in a log, a line in a text file), and the limit:

```
sfr: log flight.ulg: the number of events exceeds the input limit of 100000 events (SPEC B1.4)
sfr: rules file rules.toml: line 3: `required_topics` exceeds the input limit of 256 entries (SPEC B1.4)
```

| Command | Input | Exit code |
|---|---|---|
| `seal` | log, rules file, baseline | 3 |
| `seal`, `keygen`, `verify` (Chunk 3) | key file, public key | 4 |
| `verify` (Chunk 3) | record, or the log given with `--ulog` | 1 (verification failed) |

## The limits

| Limit | Value | Why | Enforced in |
|---|---|---|---|
| ULog file format version | 0 or 1 | Later versions may change the layout; `sfr` refuses rather than guesses. | `ulog.rs` |
| Format nesting | 8 levels | Nested types are flattened recursively; the cap bounds the recursion. | `ulog.rs` `MAX_NESTING` |
| One flattened format | 65,535 bytes, 65,535 fields | A data record's length field is 16 bits, so no record can be longer. Every field is at least one byte, so the byte limit is reached first. | `ulog.rs` `MAX_LAYOUT_SIZE` |
| Array length | 1 to 65,535 | Same 16-bit bound; zero-length arrays have no meaning. | `ulog.rs` |
| Fields across all format definitions | 1,000,000 | Bounds the memory held by the definitions section. | `ulog.rs` `MAX_TOTAL_FIELDS` |
| Flattened fields across all subscriptions | 1,000,000 | A format can be subscribed many times; each subscription holds its own flattened layout. | `ulog.rs` `MAX_TOTAL_FIELDS` |
| Flattened field name, subscription name | 255 bytes | The cap bounds the text kept per field. | `ulog.rs` `MAX_NAME_LEN` |
| Parameter name | 1 to 16 letters, digits, `_` | The PX4 parameter name rule. | `params.rs` `valid_param_name` |
| Parameters at log start | 65,536 | The cap bounds the parameter table. | `ingest.rs` with `params.rs` `MAX_PARAMS` |
| `failsafe_flags` flag fields | 256 | Failsafe events name the flags that changed, so the count bounds each event. | `ingest.rs` `MAX_FAILSAFE_FLAGS` |
| Events | 100,000 | A crafted log (a failsafe that toggles on every row, for example) could otherwise build a timeline and a record that exhaust memory. This is ten times the size at which SPEC B1.10 measures standalone verify. | `events.rs` `MAX_EVENTS` |
| Rules file, baseline, key file, public key | 16 MiB each | These are small text files; the cap stops `sfr` reading an unbounded file into memory. | `sfr/src/main.rs` `MAX_TEXT_BYTES` |
| `required_topics.topics`, `parameters.ignore` | 256 entries each | Bounds the work done per log. | `rules.rs` `MAX_LIST_ENTRIES` |
| Topic name | 1 to 64 lowercase letters, digits, `_` | The uORB topic name rule. | `rules.rs` `valid_topic` |
| Parameter name pattern | 1 to 64 characters, at most 8 `*` | Wildcard matching cost grows with the number of `*`; the cap keeps it small. | `params.rs` `MAX_PATTERN_STARS` |
| Baseline parameters | 65,536 | Same as parameters at log start. | `params.rs` `MAX_PARAMS` |
| Record (Chunk 3) | 512 MiB | The cap stops `verify` reading an unbounded file. | `verify` arrives in Chunk 3 |
| Record JSON nesting (Chunk 3) | 64 levels | The cap bounds the parser's recursion. | `verify` arrives in Chunk 3 |

The log itself has no size limit. It is read as a stream in one pass, and memory is bounded by the limits above, not by the file size.

## One limit that truncates

A rule's `detail` lists at most 1,000 lines (`evaluate.rs` `MAX_DETAIL_LINES`). Past that it ends with one line, `and N more; the events list every one`. This is not an error: the record's events still list every occurrence, and the rule's status is unchanged.

## Testing

Unit tests in `ulog.rs`, `ingest.rs`, `events.rs`, `rules.rs`, and `params.rs` cross each limit and check that the message names it; most also check that an input exactly at the limit is accepted. `crates/sfr/tests/seal_dry_run.rs` checks the 16 MiB text file limit for a rules file (exit 3). The record limits arrive with `verify` in Chunk 3. One limit has no crossing test: the 65,535 fields per format limit (the byte limit is always reached first). The fuzz targets (`fuzz/`) run with `-rss_limit_mb=2048` and `-timeout=10`, so an input that escapes a limit shows up as a fuzz failure.
