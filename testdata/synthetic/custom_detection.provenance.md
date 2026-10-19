# custom_detection.ulg

Synthetic. Written by `scripts/testdata/make_synthetic_logs.py` (Python standard library only); not a flight and not a third-party log. Regenerate with:

```
python3 -I scripts/testdata/make_synthetic_logs.py testdata/synthetic
```

It proves that sealed topics need no knowledge of the topic. The log carries a topic PX4 does not define, `custom_detection`, whose format uses a nested type (`detection_box`):

```
detection_box:float x;float y;float w;float h;
custom_detection:uint64_t timestamp;uint32_t class_id;float confidence;detection_box box;
```

It is subscribed in three instances: instance 0 has five data records, instance 1 has two, and instance 2 has none. `vehicle_status` and `failsafe_flags` use PX4 field names and types for a multicopter that arms at 2 s and disarms at 7 s, never in failsafe; firmware is reported as v1.17.0. The golden rules file `testdata/rules/synthetic_custom_detection.toml` is the default rules plus `[sealed_topics] topics = ["custom_detection"]`, so the expected file holds three sealed topic digests.

| Field | Value |
|---|---|
| SHA-256 | `80fb3f281fb9642a75e8289d9080a24be85669328d4f044cafdb3da68d4ae108` |
| Size | 1338 bytes |
