// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Timestamps, durations and change windows, without a clock and without a
//! time-zone database.
//!
//! The engine never reads the time: the host passes `time.now` (and the
//! workspace time zone with its UTC offset at that instant) in the
//! [`EvalContext`](crate::policy::EvalContext). Everything here is pure
//! arithmetic on those values, so a policy evaluates the same way in the
//! proxy, the Runtime API and the simulator (which passes the event's
//! `occurred_at`).

use std::fmt::Write as _;

/// A timestamp: seconds since the Unix epoch and a nanosecond fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Ts {
    pub(crate) secs: i64,
    pub(crate) nanos: u32,
}

/// CEL's timestamp range: 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z.
const MIN_SECS: i64 = -62_135_596_800;
const MAX_SECS: i64 = 253_402_300_799;

impl Ts {
    pub(crate) fn from_secs(secs: i64) -> Option<Ts> {
        (MIN_SECS..=MAX_SECS)
            .contains(&secs)
            .then_some(Ts { secs, nanos: 0 })
    }

    fn total_nanos(self) -> i128 {
        i128::from(self.secs) * 1_000_000_000 + i128::from(self.nanos)
    }

    fn from_total_nanos(n: i128) -> Option<Ts> {
        let secs = n.div_euclid(1_000_000_000);
        let nanos = n.rem_euclid(1_000_000_000) as u32;
        let secs = i64::try_from(secs).ok()?;
        (MIN_SECS..=MAX_SECS)
            .contains(&secs)
            .then_some(Ts { secs, nanos })
    }

    pub(crate) fn plus_nanos(self, d: i64) -> Option<Ts> {
        Ts::from_total_nanos(self.total_nanos() + i128::from(d))
    }

    pub(crate) fn nanos_since(&self, other: &Ts) -> Option<i64> {
        i64::try_from(self.total_nanos() - other.total_nanos()).ok()
    }

    pub(crate) fn to_rfc3339(self) -> String {
        let days = self.secs.div_euclid(86_400);
        let sod = self.secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let mut s = format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
            sod / 3600,
            (sod % 3600) / 60,
            sod % 60
        );
        if self.nanos != 0 {
            let frac = format!("{:09}", self.nanos);
            let _ = write!(s, ".{}", frac.trim_end_matches('0'));
        }
        s.push('Z');
        s
    }
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) → days since 1970-01-01.
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Parses an RFC 3339 timestamp (`2026-10-21T14:05:00Z`,
/// `2026-10-21T16:05:00.5+02:00`). With `lenient`, also an ISO date
/// (`2026-10-21`, midnight UTC) and a space instead of `T` with no offset
/// (UTC), which is how SQL date and timestamp literals are written.
pub(crate) fn parse_timestamp(s: &str, lenient: bool) -> Option<Ts> {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        (!t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()))
            .then(|| t.parse().ok())
            .flatten()
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y = digits(0..4)?;
    let m = u32::try_from(digits(5..7)?).ok()?;
    let d = u32::try_from(digits(8..10)?).ok()?;
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    if b.len() == 10 {
        return lenient.then(|| Ts::from_secs(days * 86_400)).flatten();
    }
    if !(b[10] == b'T' || b[10] == b't' || (lenient && b[10] == b' ')) || b.len() < 19 {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let hh = digits(11..13)?;
    let mm = digits(14..16)?;
    let ss = digits(17..19)?;
    if hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let mut i = 19;
    let mut nanos: u32 = 0;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[start..i];
        if frac.is_empty() || frac.len() > 9 {
            return None;
        }
        nanos = format!("{frac:0<9}").parse().ok()?;
    }
    let offset = match &s[i..] {
        "Z" | "z" => 0,
        "" if lenient => 0,
        rest => parse_offset(rest)?,
    };
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss.min(59) - i64::from(offset);
    let ts = Ts::from_secs(secs)?;
    Some(Ts { nanos, ..ts })
}

/// `+HH:MM` / `-HH:MM` → seconds east of UTC.
pub(crate) fn parse_offset(s: &str) -> Option<i32> {
    let b = s.as_bytes();
    if b.len() != 6 || b[3] != b':' || !matches!(b[0], b'+' | b'-') {
        return None;
    }
    let hh: i32 = s.get(1..3)?.parse().ok()?;
    let mm: i32 = s.get(4..6)?.parse().ok()?;
    if hh > 23 || mm > 59 {
        return None;
    }
    let v = hh * 3600 + mm * 60;
    Some(if b[0] == b'-' { -v } else { v })
}

/// Parses a CEL / Go duration: `2160h`, `1h30m`, `90s`, `1.5h`, `250ms`,
/// `-5m`. Returns nanoseconds.
pub(crate) fn parse_duration(s: &str) -> Option<i64> {
    let (neg, mut rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if rest == "0" {
        return Some(0);
    }
    if rest.is_empty() {
        return None;
    }
    let mut total: i128 = 0;
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let (num, after) = rest.split_at(end);
        if num.is_empty() || num == "." {
            return None;
        }
        let unit_end = after
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(after.len());
        let (unit, next) = after.split_at(unit_end);
        let scale: i128 = match unit {
            "h" => 3_600_000_000_000,
            "m" => 60_000_000_000,
            "s" => 1_000_000_000,
            "ms" => 1_000_000,
            "us" | "µs" => 1_000,
            "ns" => 1,
            _ => return None,
        };
        let (int_part, frac_part) = num.split_once('.').unwrap_or((num, ""));
        let int: i128 = if int_part.is_empty() {
            0
        } else {
            int_part.parse().ok()?
        };
        let mut v = int.checked_mul(scale)?;
        if !frac_part.is_empty() {
            let digits = frac_part.len().min(18) as u32;
            let frac: i128 = frac_part.get(..digits as usize)?.parse().ok()?;
            v = v.checked_add(frac.checked_mul(scale)? / 10i128.pow(digits))?;
        }
        total = total.checked_add(v)?;
        rest = next;
    }
    let total = if neg { -total } else { total };
    i64::try_from(total).ok()
}

/// CEL's `string(duration)`: seconds with an `s` suffix (`5400s`, `1.5s`).
pub(crate) fn format_duration(nanos: i64) -> String {
    let secs = nanos / 1_000_000_000;
    let frac = (nanos % 1_000_000_000).unsigned_abs();
    if frac == 0 {
        format!("{secs}s")
    } else {
        let sign = if nanos < 0 && secs == 0 { "-" } else { "" };
        let f = format!("{frac:09}");
        format!("{sign}{secs}.{}s", f.trim_end_matches('0'))
    }
}

// ---------------------------------------------------------------------------
// Local time and change windows

/// Local calendar fields of an instant at a UTC offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Local {
    pub(crate) year: i64,
    pub(crate) month: u32,
    pub(crate) day: u32,
    /// 0 = Monday … 6 = Sunday.
    pub(crate) weekday: u32,
    pub(crate) minute_of_day: u32,
}

pub(crate) fn local(ts: Ts, offset_secs: i32) -> Local {
    let t = ts.secs + i64::from(offset_secs);
    let days = t.div_euclid(86_400);
    let sod = t.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday (3 with Monday = 0).
    let weekday = (days + 3).rem_euclid(7) as u32;
    Local {
        year,
        month,
        day,
        weekday,
        minute_of_day: (sod / 60) as u32,
    }
}

/// A set of weekly windows: `Mon-Fri 09:00-18:00`, `Tue,Thu 14:00-16:00`,
/// several separated by `;`. A window whose end is not after its start
/// (`22:00-06:00`) runs past midnight into the next day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowSpec {
    windows: Vec<Window>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Window {
    /// Bit i set: the window starts on weekday i (0 = Monday).
    days: u8,
    start: u32,
    end: u32,
}

const DAY_NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn day_index(s: &str) -> Option<u32> {
    let s = s.trim().to_ascii_lowercase();
    let key = s.get(..3)?;
    let full = [
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ];
    let i = DAY_NAMES.iter().position(|d| *d == key)?;
    // `Mon` and `Monday`, nothing in between that is not a prefix.
    (full[i].starts_with(s.as_str())).then_some(i as u32)
}

fn hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.trim().split_once(':')?;
    let h: u32 = h.parse().ok()?;
    let m: u32 = m.parse().ok()?;
    if m > 59 || h > 24 || (h == 24 && m != 0) || h.to_string().len() > 2 {
        return None;
    }
    Some(h * 60 + m)
}

impl WindowSpec {
    pub(crate) fn parse(spec: &str) -> Result<WindowSpec, String> {
        let mut windows = Vec::new();
        for part in spec.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (days_s, times_s) = part.split_once(char::is_whitespace).ok_or_else(|| {
                format!("window `{part}` needs days and hours, e.g. `Mon-Fri 09:00-18:00`")
            })?;
            let mut days: u8 = 0;
            for item in days_s.split(',') {
                match item.split_once('-') {
                    Some((a, b)) => {
                        let (a, b) = (
                            day_index(a).ok_or_else(|| format!("unknown day `{a}`"))?,
                            day_index(b).ok_or_else(|| format!("unknown day `{b}`"))?,
                        );
                        let mut d = a;
                        loop {
                            days |= 1 << d;
                            if d == b {
                                break;
                            }
                            d = (d + 1) % 7;
                        }
                    }
                    None => {
                        let d = day_index(item).ok_or_else(|| format!("unknown day `{item}`"))?;
                        days |= 1 << d;
                    }
                }
            }
            let (a, b) = times_s
                .trim()
                .split_once('-')
                .ok_or_else(|| format!("window `{part}` needs a time range, e.g. 09:00-18:00"))?;
            let start = hhmm(a).ok_or_else(|| format!("invalid time `{a}`"))?;
            let end = hhmm(b).ok_or_else(|| format!("invalid time `{b}`"))?;
            if start == end {
                return Err(format!("window `{part}` is empty"));
            }
            windows.push(Window { days, start, end });
        }
        if windows.is_empty() {
            return Err("no window given".into());
        }
        Ok(WindowSpec { windows })
    }

    /// Whether local time `l` falls in any window. Start inclusive, end
    /// exclusive.
    pub(crate) fn contains(&self, l: Local) -> bool {
        let m = l.minute_of_day;
        let today = l.weekday;
        let yesterday = (l.weekday + 6) % 7;
        self.windows.iter().any(|w| {
            if w.start < w.end {
                w.days & (1 << today) != 0 && m >= w.start && m < w.end
            } else {
                // Overnight: the part before midnight belongs to its start
                // day, the part after midnight to the day before.
                (w.days & (1 << today) != 0 && m >= w.start)
                    || (w.days & (1 << yesterday) != 0 && m < w.end)
            }
        })
    }
}

/// The time zone argument of `in_window`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TzSpec {
    Fixed(i32),
    /// A zone name: only decidable when it is the zone the host passed.
    Named(String),
}

impl TzSpec {
    pub(crate) fn parse(s: &str) -> TzSpec {
        match s {
            "UTC" | "utc" | "Z" | "Etc/UTC" | "GMT" => TzSpec::Fixed(0),
            other => match parse_offset(other) {
                Some(o) => TzSpec::Fixed(o),
                None => TzSpec::Named(other.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip() {
        for days in [-719_468i64, -1, 0, 1, 365, 10_957, 20_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_747), (2026, 10, 21));
    }

    #[test]
    fn timestamps() {
        let t = parse_timestamp("2026-10-21T14:05:00Z", false).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-21T14:05:00Z");
        let o = parse_timestamp("2026-10-21T16:05:00+02:00", false).unwrap();
        assert_eq!(o, t);
        let f = parse_timestamp("2026-10-21T14:05:00.250Z", false).unwrap();
        assert_eq!(f.nanos, 250_000_000);
        assert_eq!(f.to_rfc3339(), "2026-10-21T14:05:00.25Z");
        assert!(parse_timestamp("2026-10-21", false).is_none());
        assert_eq!(
            parse_timestamp("2026-10-21", true).unwrap().to_rfc3339(),
            "2026-10-21T00:00:00Z"
        );
        assert_eq!(parse_timestamp("2026-10-21 14:05:00", true), Some(t));
        assert!(parse_timestamp("2026-02-30", true).is_none());
        assert!(parse_timestamp("2026-13-01T00:00:00Z", false).is_none());
        assert!(parse_timestamp("not a date", true).is_none());
        assert!(parse_timestamp("2026-10-21T14:05:00", false).is_none());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("2160h"), Some(2160 * 3_600_000_000_000));
        assert_eq!(parse_duration("1h30m"), Some(5_400_000_000_000));
        assert_eq!(parse_duration("1.5h"), Some(5_400_000_000_000));
        assert_eq!(parse_duration("-250ms"), Some(-250_000_000));
        assert_eq!(parse_duration("0"), Some(0));
        assert!(parse_duration("").is_none());
        assert!(parse_duration("5").is_none());
        assert!(parse_duration("5d").is_none());
        assert!(parse_duration("999999999999h").is_none());
        assert_eq!(format_duration(5_400_000_000_000), "5400s");
        assert_eq!(format_duration(1_500_000_000), "1.5s");
    }

    #[test]
    fn windows() {
        let w = WindowSpec::parse("Mon-Fri 09:00-18:00").unwrap();
        // 2026-10-21 is a Wednesday.
        let wed_10 = parse_timestamp("2026-10-21T10:00:00Z", false).unwrap();
        assert!(w.contains(local(wed_10, 0)));
        // 10:00 UTC is 07:00 in UTC-3: outside.
        assert!(!w.contains(local(wed_10, -3 * 3600)));
        let sat = parse_timestamp("2026-10-24T10:00:00Z", false).unwrap();
        assert!(!w.contains(local(sat, 0)));
        // End exclusive.
        let at_18 = parse_timestamp("2026-10-21T18:00:00Z", false).unwrap();
        assert!(!w.contains(local(at_18, 0)));

        let night = WindowSpec::parse("Fri 22:00-06:00").unwrap();
        let fri_23 = parse_timestamp("2026-10-23T23:00:00Z", false).unwrap();
        let sat_05 = parse_timestamp("2026-10-24T05:00:00Z", false).unwrap();
        let sat_23 = parse_timestamp("2026-10-24T23:00:00Z", false).unwrap();
        assert!(night.contains(local(fri_23, 0)));
        assert!(night.contains(local(sat_05, 0)));
        assert!(!night.contains(local(sat_23, 0)));

        let two = WindowSpec::parse("Tue,Thu 14:00-16:00; Sat-Sun 00:00-24:00").unwrap();
        assert!(two.contains(local(sat, 0)));
        assert!(!two.contains(local(wed_10, 0)));
        assert!(WindowSpec::parse("Mon 10:00-10:00").is_err());
        assert!(WindowSpec::parse("Funday 10:00-11:00").is_err());
        assert!(WindowSpec::parse("Mon 25:00-26:00").is_err());
        assert!(WindowSpec::parse("").is_err());
    }

    #[test]
    fn tz_specs() {
        assert_eq!(TzSpec::parse("UTC"), TzSpec::Fixed(0));
        assert_eq!(TzSpec::parse("-03:00"), TzSpec::Fixed(-10_800));
        assert_eq!(
            TzSpec::parse("Europe/Madrid"),
            TzSpec::Named("Europe/Madrid".into())
        );
    }
}
