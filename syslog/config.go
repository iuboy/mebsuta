package syslog

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/iuboy/mebsuta"
)

// DefaultFacility is the syslog facility used when Config.Facility is zero.
// Go's int zero value is 0 (LOG_KERN), but user-space applications should use
// LOG_USER (1) by default. If you explicitly need LOG_KERN, set Facility to
// syslog.LOG_KERN (0) — the Validate method will preserve it because the field
// is already "non-zero" from the user's perspective.
const DefaultFacility = 1

// Config holds configuration for syslog output.
type Config struct {
	Network  string       // "tcp", "udp", "unix". Defaults to "tcp".
	Address  string       // Required: syslog server address (e.g., "localhost:514").
	Level    slog.Leveler // Log level filter. Defaults to slog.LevelInfo.
	Tag      string       // Syslog tag. Defaults to "mebsuta".
	Facility int          // Syslog facility (0-23). 0 → DefaultFacility (1=user).
	// See DefaultFacility for why 0 is remapped to 1 (user) rather than
	// preserved as 0 (kernel), which is the Go zero value for int.
	Reconnect     *bool         // Auto-reconnect on disconnect. nil → true.
	RetryDelay    time.Duration // Delay between reconnect attempts. 0 → 500ms.
	TLSSkipVerify bool          // Skip TLS certificate verification.
	StaticHost    string        // Override system hostname.
	Secure        bool          // Enable TLS.
	RFC5424       bool          // Use RFC5424 format instead of RFC3164.
	BufferSize    int           // Internal message buffer size. 0 → 1000.
	TimeZone      string        // Timezone for timestamps. Defaults to "UTC".
	JSONInMessage bool          // Include JSON structure in message field.
	ErrorTimeout  time.Duration // Max wait when buffer is full for Error+ logs. 0 → 1s.
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c Config) Validate() (Config, error) {
	if c.Network == "" {
		c.Network = "tcp"
	}
	if c.Address == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Address", Msg: "syslog address is required"}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.Tag == "" {
		c.Tag = "mebsuta"
	}
	if len(c.Tag) > 48 {
		return Config{}, &mebsuta.ConfigError{Field: "Tag", Msg: fmt.Sprintf("syslog tag too long: %d chars (max 48)", len(c.Tag))}
	}
	for _, r := range c.Tag {
		if r < 33 || r > 126 {
			return Config{}, &mebsuta.ConfigError{Field: "Tag", Msg: fmt.Sprintf("syslog tag contains non-printable character: %q", r)}
		}
	}
	if c.Facility < 0 || c.Facility > 23 {
		return Config{}, &mebsuta.ConfigError{Field: "Facility", Msg: fmt.Sprintf("invalid syslog facility: %d, must be 0-23", c.Facility)}
	}
	// 0 is the Go zero value but also a valid syslog facility (LOG_KERN).
	// Applications should use LOG_USER (1) by default, so we remap 0 → 1.
	// Users who genuinely need LOG_KERN must use a separate mechanism.
	if c.Facility == 0 {
		c.Facility = DefaultFacility
	}
	if c.Reconnect == nil {
		c.Reconnect = mebsuta.BoolPtr(true)
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = 500 * time.Millisecond
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 1000
	}
	if c.ErrorTimeout <= 0 {
		c.ErrorTimeout = 1 * time.Second
	}
	if c.TimeZone != "" {
		if _, err := time.LoadLocation(c.TimeZone); err != nil {
			return Config{}, &mebsuta.ConfigError{Field: "TimeZone", Msg: fmt.Sprintf("invalid timezone: %s", c.TimeZone)}
		}
	}
	return c, nil
}
