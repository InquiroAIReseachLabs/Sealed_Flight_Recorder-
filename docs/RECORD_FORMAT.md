# Record format (`.sfr`)

SPEC B1.7 defines the record. Chunk 7 completes this document: every field, the leaf layout, and copy-paste `openssl` and `b3sum` commands that check a record without `sfr`. Change Order 01 requires the sealed topic digest byte layout now, so that an independent implementation can reproduce it; it is below.

## Event field `initial`

ARM and FAILSAFE_SET events carry a boolean `initial` (SPEC B1.5); no other event kind has it. It is `true` when the event comes from the log's first `vehicle_status` sample, because the log starts armed (ARM) or with `vehicle_status.failsafe` true (FAILSAFE_SET): the event records the state the log opens in, not a change the log shows. It is `false` when the event is a change from the previous `vehicle_status` sample in file order. The report shows the field in the detail column of its event timeline, with this definition in one line under the table.

## Sealed topic digests

A rules file may list topics in `[sealed_topics]` (at most 64). For each listed topic and each instance (`multi_id`) the log subscribes, the record holds one entry in `sealed_topics`. The tool needs no knowledge of the topic's message structure: ULog is self-describing.

### Inputs

The ULog file, read once in file order: the definitions section, the data section, and appended data as the ULog file format describes it. Record layouts below are those of the ULog file format: a 3-byte header (`msg_size` as uint16 little-endian, then `msg_type`), then `msg_size` bytes of payload.

### Procedure

1. **'F' records (format definitions).** The payload is the text `<name>:<fields>` exactly as stored. When `<name>` is a sealed topic, remember `format_sha256[name] = SHA-256(payload)`. A later 'F' record with the same name replaces it.
2. **'A' records (subscriptions).** The payload is `multi_id` (uint8), `msg_id` (uint16 little-endian), then the message name. When the name is a sealed topic and no entry exists yet for (name, `multi_id`), create one: `format_sha256` from step 1 as it stands at this point, `message_count` 0, no timestamps, and a fresh SHA-256 context `H`. Either way, `msg_id` now refers to that entry.
3. **'D' records (data).** The payload is `msg_id` (uint16 little-endian), then the message bytes `P`: every byte after the message id, padding included. When `msg_id` refers to an entry:
   - `message_count` += 1;
   - `t` = the message's own `timestamp` field (uint64 little-endian, at the offset the topic's flattened format gives it; every ULog format has one);
   - `first_timestamp_us` = `t` of the first such record; `last_timestamp_us` = `t` of the latest;
   - `H.update(le64(len(P)))`, then `H.update(P)`, where `le64` is the 8-byte little-endian encoding.

   The message id is left out because a log assigns it, so it differs between logs that carry the same messages.
4. **Entries.** At the end of the log, each entry is the JSON object below. Entries are sorted by `topic` (byte order), then `multi_id`.

| Field | Value |
|---|---|
| `topic` | the message name |
| `multi_id` | integer |
| `format_sha256` | lowercase hex |
| `message_count` | integer |
| `first_timestamp_us`, `last_timestamp_us` | decimal string, or null when `message_count` is 0 |
| `data_sha256` | lowercase hex of `H`'s digest (the SHA-256 of no bytes when `message_count` is 0) |

5. **Leaves.** Each entry is one Merkle leaf, SHA-256(0x00 || JCS(entry)), after the results' leaves and before the events' leaves (SPEC B1.7).

`format_sha256` covers the topic's own 'F' record only, not the 'F' records of nested types it uses.

### Worked example

The unit test `ingest.rs` `sealed_topics_are_digested_per_instance_while_streaming` builds this log and checks these values.

- 'F' payload: `custom_detection:uint64_t timestamp;uint8_t[4] box;`
- `format_sha256`: `c05f82794614bc08b65ab3dbf5920fb43e7ffbda890061d06e79cfa5364d6143`
- Instance 0 has two data records. Their message bytes are `0a0000000000000001020304` (timestamp 10) and `140000000000000005060708` (timestamp 20), each 12 bytes long.
- `data_sha256` = SHA-256(`0c00000000000000` `0a0000000000000001020304` `0c00000000000000` `140000000000000005060708`) = `a933532016ce84d3fa02c2b0e1f09bab760869b1320c9450571b2f62c4eab43c`
- `message_count` 2, `first_timestamp_us` `"10"`, `last_timestamp_us` `"20"`.
- Instance 1 is subscribed with no data records: `message_count` 0, both timestamps null, `data_sha256` `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
