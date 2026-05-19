use std::path::Path;

use serde::Deserialize;

use crate::error::Error;
use crate::level::Level;
use crate::record::EventType;

/// Top-level configuration for the entire mebsuta handler pipeline.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct MebsutaConfig {
    pub level: String,
    pub format: String,
    pub stdout: StdoutConfig,
    pub file: FileConfig,
    pub database: DatabaseConfig,
    pub syslog: SyslogConfig,
    pub sampling: SamplingConfig,
    pub r#async: AsyncConfig,
}

impl Default for MebsutaConfig {
    fn default() -> Self {
        MebsutaConfig {
            level: "info".to_owned(),
            format: "json".to_owned(),
            stdout: StdoutConfig::default(),
            file: FileConfig::default(),
            database: DatabaseConfig::default(),
            syslog: SyslogConfig::default(),
            sampling: SamplingConfig::default(),
            r#async: AsyncConfig::default(),
        }
    }
}

impl MebsutaConfig {
    pub fn parse_json(s: &str) -> Result<Self, Error> {
        let config: MebsutaConfig = serde_json::from_str(s)?;
        Ok(config)
    }

    pub fn parse_json_reader<R: std::io::Read>(r: R) -> Result<Self, Error> {
        let config: MebsutaConfig = serde_json::from_reader(r)?;
        Ok(config)
    }

    pub fn level(&self) -> Result<Level, Error> {
        parse_level(&self.level)
    }

    pub fn format(&self) -> Result<crate::stdout::Format, Error> {
        parse_format(&self.format)
    }

    pub fn validate(&mut self) -> Result<(), Error> {
        // Validate level
        self.level()?;

        // Validate format
        self.format()?;

        // Validate sub-configs
        self.file.validate()?;
        self.database.validate()?;
        self.syslog.validate()?;
        self.sampling.validate()?;

        Ok(())
    }
}

fn parse_level(s: &str) -> Result<Level, Error> {
    match s.to_lowercase().as_str() {
        "error" => Ok(Level::Error),
        "warn" | "warning" => Ok(Level::Warn),
        "audit" => Ok(Level::Audit(EventType::System)),
        "info" => Ok(Level::Info),
        "debug" => Ok(Level::Debug),
        "trace" => Ok(Level::Trace),
        _ => Err(Error::Config(format!("invalid log level: {s}"))),
    }
}

fn parse_format(s: &str) -> Result<crate::stdout::Format, Error> {
    match s.to_lowercase().as_str() {
        "json" => Ok(crate::stdout::Format::Json),
        "text" | "console" => Ok(crate::stdout::Format::Text),
        _ => Err(Error::Config(format!("invalid format: {s}"))),
    }
}

// ---------------------------------------------------------------------------
// Sub-configs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct StdoutConfig {
    pub enabled: bool,
}

impl Default for StdoutConfig {
    fn default() -> Self {
        StdoutConfig { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct FileConfig {
    pub enabled: bool,
    pub path: String,
    pub max_size_bytes: u64,
    pub rotate_interval_secs: u64,
    pub max_backups: usize,
    pub max_age_days: u32,
    pub compress: bool,
}

impl Default for FileConfig {
    fn default() -> Self {
        FileConfig {
            enabled: false,
            path: String::new(),
            max_size_bytes: 100 * 1024 * 1024,
            rotate_interval_secs: 0,
            max_backups: 5,
            max_age_days: 180,
            compress: false,
        }
    }
}

impl FileConfig {
    pub fn validate(&mut self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }
        if self.path.is_empty() {
            return Err(Error::Config("file path is required".to_owned()));
        }
        if !Path::new(&self.path).is_absolute() {
            return Err(Error::Config(format!(
                "file path must be absolute: {}",
                self.path
            )));
        }
        if self.max_size_bytes == 0 {
            self.max_size_bytes = 100 * 1024 * 1024;
        }
        Ok(())
    }

    pub fn to_rotation_config(&self) -> crate::file::RotationConfig {
        crate::file::RotationConfig {
            max_size_bytes: self.max_size_bytes,
            rotate_interval_secs: self.rotate_interval_secs,
            max_backups: self.max_backups,
            max_age_days: self.max_age_days,
            compress: self.compress,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct DatabaseConfig {
    pub enabled: bool,
    pub path: String,
    pub table: String,
    pub batch_size: usize,
    pub batch_interval_secs: u64,
    pub retry_delay_ms: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            enabled: false,
            path: String::new(),
            table: "logs".to_owned(),
            batch_size: 100,
            batch_interval_secs: 5,
            retry_delay_ms: 500,
        }
    }
}

impl DatabaseConfig {
    pub fn validate(&mut self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }
        if self.path.is_empty() {
            return Err(Error::Config("database path is required".to_owned()));
        }
        if self.batch_size == 0 {
            self.batch_size = 100;
        }
        if self.batch_interval_secs == 0 {
            self.batch_interval_secs = 5;
        }
        if self.retry_delay_ms == 0 {
            self.retry_delay_ms = 500;
        }
        validate_table_name(&self.table)?;
        Ok(())
    }

    pub fn to_db_config(&self, _level: Level) -> crate::database::DatabaseConfig {
        crate::database::DatabaseConfig {
            path: self.path.clone(),
            table: self.table.clone(),
            batch_size: self.batch_size,
            batch_interval_secs: self.batch_interval_secs,
            retry_delay_ms: self.retry_delay_ms,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SyslogConfig {
    pub enabled: bool,
    pub transport: String,
    pub address: String,
    pub tag: String,
    pub hostname: String,
    pub facility: u8,
    pub format: String,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        SyslogConfig {
            enabled: false,
            transport: "udp".to_owned(),
            address: "127.0.0.1:514".to_owned(),
            tag: "mebsuta".to_owned(),
            hostname: String::new(),
            facility: 1,
            format: "rfc3164".to_owned(),
        }
    }
}

impl SyslogConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }
        if self.address.is_empty() {
            return Err(Error::Config("syslog address is required".to_owned()));
        }
        if self.facility > 23 {
            return Err(Error::Config(format!(
                "invalid syslog facility: {}, must be 0-23",
                self.facility
            )));
        }
        Ok(())
    }

    pub fn to_syslog_config(&self) -> crate::syslog::SyslogConfig {
        let transport = match self.transport.to_lowercase().as_str() {
            "tcp" => crate::syslog::SyslogTransport::Tcp,
            _ => crate::syslog::SyslogTransport::Udp,
        };
        let format = match self.format.to_lowercase().as_str() {
            "rfc5424" => crate::syslog::SyslogFormat::RFC5424,
            _ => crate::syslog::SyslogFormat::RFC3164,
        };
        let hostname = if self.hostname.is_empty() {
            std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("hostname"))
                .unwrap_or_else(|_| "localhost".to_owned())
        } else {
            self.hostname.clone()
        };
        crate::syslog::SyslogConfig {
            transport,
            format,
            address: self.address.clone(),
            tag: self.tag.clone(),
            hostname,
            facility: self.facility,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SamplingConfig {
    pub enabled: bool,
    pub initial: u64,
    pub thereafter: u64,
    pub window_ticks: u64,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        SamplingConfig {
            enabled: false,
            initial: 100,
            thereafter: 100,
            window_ticks: 1000,
        }
    }
}

impl SamplingConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }
        if self.initial == 0 || self.thereafter == 0 || self.window_ticks == 0 {
            return Err(Error::Config(
                "sampling requires positive initial, thereafter and window_ticks".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct AsyncConfig {
    pub enabled: bool,
    pub buffer_size: usize,
}

impl Default for AsyncConfig {
    fn default() -> Self {
        AsyncConfig {
            enabled: false,
            buffer_size: 256,
        }
    }
}

pub(crate) fn validate_table_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::Config("table name is required".to_owned()));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(Error::Config(format!(
            "invalid table name: {name}, must start with letter or underscore"
        )));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(Error::Config(format!(
            "invalid table name: {name}, only letters, digits and underscores allowed"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sanitizer (password masking for DSN strings)
// ---------------------------------------------------------------------------

/// Mask password in a database connection string for safe logging.
pub fn mask_dsn_password(dsn: &str) -> String {
    // URI format: scheme://user:password@host/db
    if let Some(idx) = dsn.find("://")
        && let Some(at_pos) = dsn[idx + 3..].find('@')
    {
        let prefix = &dsn[..idx + 3];
        let rest = &dsn[idx + 3..];
        let credentials_end = at_pos + idx + 3;
        if let Some(colon_pos) = rest.find(':')
            && colon_pos < at_pos
        {
            let user = &rest[..colon_pos];
            return format!("{}{}:****{}", prefix, user, &dsn[credentials_end..]);
        }
    }
    // key=value format: password=xxx (space or & delimited)
    if let Some(idx) = dsn.find("password=") {
        let start = idx + 9;
        let rest = &dsn[start..];
        let end = rest
            .find('&')
            .or_else(|| rest.find(' '))
            .map_or(dsn.len(), |p| start + p);
        return format!("{}****{}", &dsn[..start], &dsn[end..]);
    }
    if dsn.len() > 20 {
        let boundary = dsn
            .char_indices()
            .take_while(|(i, c)| *i + c.len_utf8() <= 20)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        format!("{}...(hidden)", &dsn[..boundary])
    } else {
        "(hidden)".to_owned()
    }
}

/// Sanitize a config for safe logging (removes sensitive data).
pub fn sanitize_config(cfg: &MebsutaConfig) -> String {
    let db_path = if cfg.database.path.is_empty() {
        "(none)".to_owned()
    } else {
        mask_dsn_password(&cfg.database.path)
    };
    format!(
        "MebsutaConfig {{ level: {}, format: {}, file: {}, database: {{ path: {}, table: {} }}, syslog: {{ address: {} }} }}",
        cfg.level,
        cfg.format,
        if cfg.file.enabled {
            &cfg.file.path
        } else {
            "(disabled)"
        },
        db_path,
        cfg.database.table,
        cfg.syslog.address,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_json() {
        let json = r#"{"level": "debug", "format": "text"}"#;
        let cfg = MebsutaConfig::parse_json(json).unwrap();
        assert_eq!(cfg.level, "debug");
        assert_eq!(cfg.format, "text");
        assert!(!cfg.file.enabled);
    }

    #[test]
    fn parse_full_json() {
        let json = r#"{
            "level": "warn",
            "format": "json",
            "file": {
                "enabled": true,
                "path": "/var/log/app.log",
                "max_size_bytes": 50000000,
                "max_backups": 3,
                "compress": true
            },
            "syslog": {
                "enabled": true,
                "transport": "tcp",
                "address": "192.168.1.1:514",
                "tag": "myapp"
            },
            "sampling": {
                "enabled": true,
                "initial": 10,
                "thereafter": 50,
                "window_ticks": 500
            },
            "async": {
                "enabled": true,
                "buffer_size": 512
            }
        }"#;
        let mut cfg = MebsutaConfig::parse_json(json).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.file.enabled);
        assert!(cfg.syslog.enabled);
        assert!(cfg.sampling.enabled);
        assert!(cfg.r#async.enabled);
    }

    #[test]
    fn validate_rejects_invalid_level() {
        let mut cfg = MebsutaConfig::default();
        cfg.level = "invalid".to_owned();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_relative_path() {
        let mut cfg = MebsutaConfig::default();
        cfg.file.enabled = true;
        cfg.file.path = "relative/path.log".to_owned();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_file_path() {
        let mut cfg = MebsutaConfig::default();
        cfg.file.enabled = true;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_facility() {
        let mut cfg = MebsutaConfig::default();
        cfg.syslog.enabled = true;
        cfg.syslog.facility = 30;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_sampling() {
        let mut cfg = MebsutaConfig::default();
        cfg.sampling.enabled = true;
        cfg.sampling.initial = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_table_names() {
        assert!(validate_table_name("logs").is_ok());
        assert!(validate_table_name("_log").is_ok());
        assert!(validate_table_name("log_entries").is_ok());
        assert!(validate_table_name("").is_err());
        assert!(validate_table_name("1logs").is_err());
        assert!(validate_table_name("log-table").is_err());
    }

    #[test]
    fn mask_dsn() {
        assert_eq!(
            mask_dsn_password("postgres://admin:s3cret@db.host/mydb"),
            "postgres://admin:****@db.host/mydb"
        );
        assert_eq!(
            mask_dsn_password("host=db port=5432 password=hunter2 sslmode=disable"),
            "host=db port=5432 password=**** sslmode=disable"
        );
    }

    #[test]
    fn sanitize_output() {
        let cfg = MebsutaConfig::default();
        let s = sanitize_config(&cfg);
        assert!(s.contains("info"));
        assert!(s.contains("json"));
    }

    #[test]
    fn parse_level_variants() {
        assert_eq!(parse_level("ERROR").unwrap(), Level::Error);
        assert_eq!(parse_level("warn").unwrap(), Level::Warn);
        assert_eq!(
            parse_level("audit").unwrap(),
            Level::Audit(EventType::System)
        );
        assert_eq!(parse_level("Info").unwrap(), Level::Info);
        assert_eq!(parse_level("debug").unwrap(), Level::Debug);
        assert_eq!(parse_level("TRACE").unwrap(), Level::Trace);
    }

    #[test]
    fn disabled_configs_skip_validation() {
        let mut cfg = MebsutaConfig::default();
        // All sub-configs disabled by default, so empty paths are fine
        cfg.validate().unwrap();
    }

    // --- mask_dsn_password UTF-8 safety ---

    #[test]
    fn mask_dsn_non_ascii_host_fallback() {
        // DSN with non-ASCII hostname, falls through to the >20 branch
        let dsn = "postgresql://user:pass@数据库服务器主机名称非常长.example.com/db";
        let masked = mask_dsn_password(dsn);
        // Should mask the password
        assert!(masked.contains("****"));
        assert!(!masked.contains("pass"));
        // Result must be valid UTF-8
        assert!(std::str::from_utf8(masked.as_bytes()).is_ok());
    }

    #[test]
    fn mask_dsn_short_non_ascii() {
        // Short non-ASCII that doesn't match any pattern → "(hidden)"
        let masked = mask_dsn_password("测试");
        assert!(std::str::from_utf8(masked.as_bytes()).is_ok());
    }

    #[test]
    fn mask_dsn_long_non_ascii_fallback() {
        // No URI or key=value pattern, long non-ASCII → truncates at byte 20 boundary
        let dsn = "这是一段包含中文字符的很长的连接字符串用于测试截断";
        let masked = mask_dsn_password(dsn);
        assert!(masked.contains("...(hidden)"));
        assert!(std::str::from_utf8(masked.as_bytes()).is_ok());
        // Must not exceed original length
        assert!(masked.len() <= dsn.len() + 20); // generous bound
    }

    #[test]
    fn mask_dsn_fallback_boundary_valid_utf8() {
        // Construct a string where byte 20 falls in the middle of a 3-byte CJK char
        // "aaaaaaaaaaaaa" = 13 bytes + "你" = 3 bytes = 16, + "好" = 3 = 19, + "世" = 3 = 22
        let dsn = "aaaaaaaaaaaaa你好世界更多内容";
        assert!(dsn.len() > 20);
        let masked = mask_dsn_password(dsn);
        assert!(masked.contains("...(hidden)"));
        assert!(std::str::from_utf8(masked.as_bytes()).is_ok());
    }

    #[test]
    fn mask_dsn_fallback_emoji() {
        // 4-byte emoji near boundary
        let dsn = "aaaaaaaaaaaaaaaa🎉🎊🎁data";
        let masked = mask_dsn_password(dsn);
        assert!(masked.contains("...(hidden)"));
        assert!(std::str::from_utf8(masked.as_bytes()).is_ok());
    }
}
