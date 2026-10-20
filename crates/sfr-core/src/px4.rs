//! Lookups in the PX4 tables ([`crate::px4_tables`]), which `scripts/px4/px4_tables.py` writes
//! from the PX4-Autopilot source at each supported release tag.

use crate::ingest::Firmware;
use crate::px4_tables::{MSGS, MsgDef, RELEASES, Release};
use crate::ulog::Scalar;

/// The release tags whose definitions apply to a log: the tag its `ver_sw_release` names when that
/// is a release tag; else every tag of its minor series (a pre-release, or a patch with no tag
/// here); else, outside v1.14 to v1.17 or with no version, every tag.
pub fn releases_for(fw: &Firmware) -> Vec<&'static Release> {
    if let Some(r) = fw.release {
        let [major, minor, patch, kind] = r.to_be_bytes();
        if kind == 255
            && let Some(rel) = RELEASES.iter().find(|x| x.version == (major, minor, patch))
        {
            return vec![rel];
        }
        let series: Vec<_> = RELEASES
            .iter()
            .filter(|x| (x.version.0, x.version.1) == (major, minor))
            .collect();
        if !series.is_empty() {
            return series;
        }
    }
    RELEASES.iter().collect()
}

/// The tags as text: `v1.17.0`, or `v1.16.0 to v1.16.2`.
pub fn tags_label(releases: &[&Release]) -> String {
    match releases {
        [] => String::new(),
        [one] => one.tag.to_string(),
        [first, .., last] => format!("{} to {}", first.tag, last.tag),
    }
}

/// The message a topic is published with at a release, if PX4 defines that topic there.
pub fn msg(release: &Release, topic: &str) -> Option<&'static MsgDef> {
    release
        .topics
        .iter()
        .find(|(t, _)| *t == topic)
        .map(|(_, i)| &MSGS[*i])
}

/// The types `topic.field` has at the given releases, without repeats; empty when none of them
/// defines it.
pub fn field_types(releases: &[&Release], topic: &str, field: &str) -> Vec<Scalar> {
    let mut out = Vec::new();
    for r in releases {
        if let Some(m) = msg(r, topic)
            && let Some((_, s)) = m.fields.iter().find(|(n, _)| *n == field)
            && !out.contains(s)
        {
            out.push(*s);
        }
    }
    out
}

/// The types `topic.field` has at any supported release.
pub fn any_field_types(topic: &str, field: &str) -> Vec<Scalar> {
    field_types(&RELEASES.iter().collect::<Vec<_>>(), topic, field)
}

/// A constant's value at a release (`msg` is the file name, such as `VehicleStatus`).
pub fn constant(release: &Release, msg_name: &str, name: &str) -> Option<i64> {
    release
        .topics
        .iter()
        .map(|(_, i)| &MSGS[*i])
        .find(|m| m.name == msg_name)
        .and_then(|m| m.constants.iter().find(|(n, _)| *n == name))
        .map(|(_, v)| *v)
}

/// The name of the constant with this prefix and value (`NAVIGATION_STATE_`, 4 gives
/// `AUTO_LOITER`), when every given release names it the same; the first such constant of each.
pub fn constant_name(
    releases: &[&Release],
    msg_name: &str,
    prefix: &str,
    value: i64,
) -> Option<&'static str> {
    let mut name = None;
    for r in releases {
        let m = r
            .topics
            .iter()
            .map(|(_, i)| &MSGS[*i])
            .find(|m| m.name == msg_name)?;
        let n = m
            .constants
            .iter()
            .find(|(n, v)| n.starts_with(prefix) && *v == value)
            .map(|(n, _)| &n[prefix.len()..])?;
        match name {
            None => name = Some(n),
            Some(prev) if prev != n => return None,
            Some(_) => {}
        }
    }
    name
}

/// The `mode_req_*` mask that applies to a `failsafe_flags` flag at any of the given releases.
pub fn mode_requirement(releases: &[&Release], flag: &str) -> Option<&'static str> {
    releases
        .iter()
        .flat_map(|r| r.mode_requirements.iter())
        .find(|(f, _)| *f == flag)
        .map(|(_, m)| *m)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fw(release: u32) -> Firmware {
        Firmware {
            release: Some(release),
            ..Firmware::default()
        }
    }

    #[test]
    fn a_release_tag_selects_itself_and_anything_else_its_series_or_every_tag() {
        assert_eq!(tags_label(&releases_for(&fw(0x0111_00FF))), "v1.17.0");
        assert_eq!(tags_label(&releases_for(&fw(0x010E_04FF))), "v1.14.4");
        // v1.16.3 is not a tag; a release candidate is not the release.
        assert_eq!(
            tags_label(&releases_for(&fw(0x0110_03FF))),
            "v1.16.0 to v1.16.2"
        );
        assert_eq!(tags_label(&releases_for(&fw(0x0111_00C0))), "v1.17.0");
        assert_eq!(
            tags_label(&releases_for(&fw(0x0112_00FF))),
            "v1.14.0 to v1.17.0"
        );
        assert_eq!(
            tags_label(&releases_for(&Firmware::default())),
            "v1.14.0 to v1.17.0"
        );
    }

    #[test]
    fn the_constants_sfr_relies_on_have_these_values_at_every_tag() {
        for r in RELEASES {
            let c = |m: &str, n: &str| constant(r, m, n);
            // events.rs: armed is arming_state 2; VTOL state from vehicle_type 1 and 2.
            assert_eq!(
                c("VehicleStatus", "ARMING_STATE_ARMED"),
                Some(2),
                "{}",
                r.tag
            );
            assert_eq!(
                c("VehicleStatus", "VEHICLE_TYPE_ROTARY_WING"),
                Some(1),
                "{}",
                r.tag
            );
            assert_eq!(
                c("VehicleStatus", "VEHICLE_TYPE_FIXED_WING"),
                Some(2),
                "{}",
                r.tag
            );
            // events.rs: an IN_PROGRESS acknowledgement is not a result.
            assert_eq!(
                c("VehicleCommandAck", "VEHICLE_CMD_RESULT_IN_PROGRESS"),
                Some(5),
                "{}",
                r.tag
            );
        }
    }

    #[test]
    fn no_supported_tag_defines_gps_invalid_and_mode_masks_are_uint32() {
        let all: Vec<_> = RELEASES.iter().collect();
        assert!(field_types(&all, "failsafe_flags", "gps_invalid").is_empty());
        for r in RELEASES {
            let m = msg(r, "failsafe_flags").unwrap();
            for (n, s) in m.fields {
                if n.starts_with("mode_req_") {
                    assert_eq!(*s, Scalar::U32, "{} {n}", r.tag);
                }
            }
        }
        // global_position_invalid_relaxed and its mask exist only from v1.17.0.
        let v14 = releases_for(&fw(0x010E_04FF));
        assert!(field_types(&v14, "failsafe_flags", "global_position_invalid_relaxed").is_empty());
        assert_eq!(
            mode_requirement(&v14, "global_position_invalid_relaxed"),
            None
        );
        let v17 = releases_for(&fw(0x0111_00FF));
        assert_eq!(
            mode_requirement(&v17, "global_position_invalid_relaxed"),
            Some("mode_req_global_position_relaxed")
        );
    }
}
