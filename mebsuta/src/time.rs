use std::time::SystemTime;

/// Convert SystemTime to RFC3339 UTC string (no chrono dependency).
pub(crate) fn system_time_to_rfc3339(t: SystemTime) -> String {
    let duration = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let nsecs = duration.subsec_nanos();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let (year, month, day) = days_to_ymd(days);
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{nsecs:09}Z"
    )
}

/// Convert days since UNIX epoch to (year, month, day).
pub(crate) fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0u64;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i as u64 + 1;
            break;
        }
        days -= md;
    }
    (year, month, days + 1)
}

pub(crate) fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Seconds since UNIX epoch.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// YYYYMMDD-HHMMSS timestamp for file backup names.
pub(crate) fn backup_timestamp() -> String {
    let secs = now_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}{month:02}{day:02}-{hours:02}{minutes:02}{seconds:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_format() {
        let now = SystemTime::now();
        let s = system_time_to_rfc3339(now);
        assert!(s.contains('T'));
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 30);
    }

    #[test]
    fn backup_timestamp_format() {
        let s = backup_timestamp();
        // YYYYMMDD-HHMMSS = 15 chars
        assert_eq!(s.len(), 15);
        assert!(s.contains('-'));
    }

    #[test]
    fn days_to_ymd_known() {
        // 1970-01-01 = day 0
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 1970-01-02 = day 1
        assert_eq!(days_to_ymd(1), (1970, 1, 2));
    }

    #[test]
    fn leap_year() {
        assert!(is_leap(2000));
        assert!(is_leap(2024));
        assert!(!is_leap(1900));
        assert!(!is_leap(2023));
    }
}
