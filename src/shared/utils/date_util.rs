use jiff::{Timestamp, SignedDuration, ToSpan};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// Type aliases để dễ dùng
pub type DateTime = Timestamp;
pub type Duration = SignedDuration;

// Wrapper functions để dễ dùng hơn
pub struct DateUtil;

impl DateUtil {
    /// Lấy thời gian hiện tại UTC
    pub fn now() -> DateTime {
        Timestamp::now()
    }

    /// Parse từ RFC3339 string
    pub fn from_rfc3339(s: &str) -> Result<DateTime, jiff::Error> {
        Timestamp::from_str(s)
    }

    /// Chuyển sang RFC3339 string
    pub fn to_rfc3339(dt: &DateTime) -> String {
        dt.to_string()
    }

    /// Chuyển sang Unix timestamp (seconds)
    pub fn to_timestamp(dt: &DateTime) -> i64 {
        dt.as_second()
    }

    /// Tạo từ Unix timestamp (seconds)
    pub fn from_timestamp(timestamp: i64) -> Result<DateTime, jiff::Error> {
        Timestamp::from_second(timestamp)
    }

    /// Tạo từ Unix timestamp (milliseconds)
    pub fn from_timestamp_millis(timestamp: i64) -> Result<DateTime, jiff::Error> {
        Timestamp::from_millisecond(timestamp)
    }

    /// Chuyển sang Unix timestamp (milliseconds)
    pub fn to_timestamp_millis(dt: &DateTime) -> i64 {
        dt.as_millisecond()
    }
}

// Duration helper functions
impl DateUtil {
    /// Tạo duration từ hours
    pub fn hours(hours: i64) -> Duration {
        SignedDuration::new(hours * 3600, 0)
    }

    /// Tạo duration từ minutes
    pub fn minutes(minutes: i64) -> Duration {
        SignedDuration::new(minutes * 60, 0)
    }

    /// Tạo duration từ days
    pub fn days(days: i64) -> Duration {
        SignedDuration::new(days * 86400, 0)
    }

    /// Tạo duration từ seconds
    pub fn seconds(seconds: i64) -> Duration {
        SignedDuration::new(seconds, 0)
    }

    /// Tạo duration từ milliseconds
    pub fn milliseconds(milliseconds: i64) -> Duration {
        SignedDuration::new(milliseconds / 1000, (milliseconds % 1000) as i32 * 1_000_000)
    }
}

// DateTime operations
impl DateUtil {
    /// Cộng duration với datetime
    pub fn add_duration(dt: &DateTime, duration: Duration) -> Result<DateTime, jiff::Error> {
        dt.checked_add(duration)
    }

    /// Trừ duration từ datetime
    pub fn sub_duration(dt: &DateTime, duration: Duration) -> Result<DateTime, jiff::Error> {
        dt.checked_sub(duration)
    }

    /// So sánh hai datetime
    pub fn is_before(dt1: &DateTime, dt2: &DateTime) -> bool {
        dt1 < dt2
    }

    /// So sánh hai datetime
    pub fn is_after(dt1: &DateTime, dt2: &DateTime) -> bool {
        dt1 > dt2
    }

    /// Kiểm tra có phải trong tương lai không
    pub fn is_future(dt: &DateTime) -> bool {
        dt > &Self::now()
    }

    /// Kiểm tra có phải trong quá khứ không
    pub fn is_past(dt: &DateTime) -> bool {
        dt < &Self::now()
    }

    /// Tính khoảng cách giữa hai datetime
    pub fn duration_between(dt1: &DateTime, dt2: &DateTime) -> Duration {
        dt2.duration_since(*dt1)
    }
}

// Convenient functions matching chrono API
impl DateUtil {
    /// Tương đương với chrono::Utc::now()
    pub fn utc_now() -> DateTime {
        Self::now()
    }

    /// Tương đương với chrono::Duration::hours()
    pub fn duration_hours(hours: i64) -> Duration {
        Self::hours(hours)
    }

    /// Tương đương với chrono::Duration::minutes()
    pub fn duration_minutes(minutes: i64) -> Duration {
        Self::minutes(minutes)
    }

    /// Tương đương với chrono::Duration::days()
    pub fn duration_days(days: i64) -> Duration {
        Self::days(days)
    }
}

// Serialization support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableDateTime(pub DateTime);

impl SerializableDateTime {
    pub fn new(dt: DateTime) -> Self {
        Self(dt)
    }

    pub fn now() -> Self {
        Self(DateUtil::now())
    }

    pub fn inner(&self) -> &DateTime {
        &self.0
    }

    pub fn into_inner(self) -> DateTime {
        self.0
    }
}

impl From<DateTime> for SerializableDateTime {
    fn from(dt: DateTime) -> Self {
        Self(dt)
    }
}

impl From<SerializableDateTime> for DateTime {
    fn from(sdt: SerializableDateTime) -> Self {
        sdt.0
    }
}

// Helper macros for common operations
#[macro_export]
macro_rules! now {
    () => {
        crate::shared::utils::date_util::DateUtil::now()
    };
}

#[macro_export]
macro_rules! duration_hours {
    ($hours:expr) => {
        crate::shared::utils::date_util::DateUtil::hours($hours)
    };
}

#[macro_export]
macro_rules! duration_minutes {
    ($minutes:expr) => {
        crate::shared::utils::date_util::DateUtil::minutes($minutes)
    };
}

#[macro_export]
macro_rules! duration_days {
    ($days:expr) => {
        crate::shared::utils::date_util::DateUtil::days($days)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_util_basic() {
        let now = DateUtil::now();
        let future = DateUtil::add_duration(&now, DateUtil::hours(1)).unwrap();
        
        assert!(DateUtil::is_before(&now, &future));
        assert!(DateUtil::is_after(&future, &now));
        assert!(DateUtil::is_future(&future));
        assert!(!DateUtil::is_past(&future));
    }

    #[test]
    fn test_duration_operations() {
        let now = DateUtil::now();
        let tomorrow = DateUtil::add_duration(&now, DateUtil::days(1)).unwrap();
        let duration = DateUtil::duration_between(&now, &tomorrow);
        
        // Check that it's approximately 1 day
        assert!(duration.get_hours() >= 23 && duration.get_hours() <= 25);
    }

    #[test]
    fn test_serialization() {
        let now = DateUtil::now();
        let serializable = SerializableDateTime::new(now);
        
        // Test JSON serialization
        let json = serde_json::to_string(&serializable).unwrap();
        let deserialized: SerializableDateTime = serde_json::from_str(&json).unwrap();
        
        assert_eq!(serializable.inner(), deserialized.inner());
    }

    #[test]
    fn test_rfc3339_conversion() {
        let now = DateUtil::now();
        let rfc3339 = DateUtil::to_rfc3339(&now);
        let parsed = DateUtil::from_rfc3339(&rfc3339).unwrap();
        
        // Should be equal within a reasonable margin
        let diff = DateUtil::duration_between(&now, &parsed);
        assert!(diff.abs().get_milliseconds() < 1000); // Less than 1 second difference
    }
} 