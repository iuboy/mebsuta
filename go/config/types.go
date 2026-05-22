package config

import "time"

const (
	DefaultRetryDelay    = 500 * time.Millisecond
	DefaultBatchSize     = 100
	DefaultBatchInterval = 5 * time.Second
	DefaultMaxOpenConns  = 10
	DefaultMaxIdleConns  = 5
	DefaultFileMaxSizeMB = 100
	DefaultMaxBackups    = 5
	DefaultMaxAgeDays    = 30
	DefaultSyslogNetwork = "tcp"
	DefaultSyslogTag     = "mebsuta"
)

// FileConfig holds configuration for file-based log output.
type FileConfig struct {
	path           string
	maxSizeMB      int
	maxBackups     int
	maxAgeDays     int
	compress       bool
	format         string
	rotateInterval time.Duration
}

// NewFileConfig creates a new FileConfig with validation.
func NewFileConfig(path string, opts ...FileConfigOption) (*FileConfig, error) {
	if path == "" {
		return nil, &ConfigError{Field: "path", Msg: "path cannot be empty"}
	}
	cfg := &FileConfig{
		path:           path,
		maxSizeMB:      DefaultFileMaxSizeMB,
		maxBackups:     DefaultMaxBackups,
		maxAgeDays:     DefaultMaxAgeDays,
		compress:       true,
		format:         "json",
		rotateInterval: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg, nil
}

// FileConfigOption is a functional option for FileConfig.
type FileConfigOption func(*FileConfig)

// WithMaxSizeMB sets the maximum size in MB before rotation.
func WithMaxSizeMB(mb int) FileConfigOption {
	return func(cfg *FileConfig) { cfg.maxSizeMB = mb }
}

// WithMaxBackups sets the maximum number of backup files to keep.
func WithMaxBackups(n int) FileConfigOption {
	return func(cfg *FileConfig) { cfg.maxBackups = n }
}

// WithMaxAgeDays sets the maximum age in days for backup files.
func WithMaxAgeDays(days int) FileConfigOption {
	return func(cfg *FileConfig) { cfg.maxAgeDays = days }
}

// WithCompress enables or disables gzip compression.
func WithCompress(compress bool) FileConfigOption {
	return func(cfg *FileConfig) { cfg.compress = compress }
}

// WithFormat sets the output format (json or text).
func WithFormat(format string) FileConfigOption {
	return func(cfg *FileConfig) { cfg.format = format }
}

// WithRotateInterval sets the time-based rotation interval.
func WithRotateInterval(d time.Duration) FileConfigOption {
	return func(cfg *FileConfig) { cfg.rotateInterval = d }
}

// Getter methods for FileConfig
func (c *FileConfig) Path() string                  { return c.path }
func (c *FileConfig) MaxSizeMB() int                { return c.maxSizeMB }
func (c *FileConfig) MaxBackups() int               { return c.maxBackups }
func (c *FileConfig) MaxAgeDays() int               { return c.maxAgeDays }
func (c *FileConfig) Compress() bool                { return c.compress }
func (c *FileConfig) Format() string                { return c.format }
func (c *FileConfig) RotateInterval() time.Duration { return c.rotateInterval }

// DatabaseConfig holds configuration for database log output.
type DatabaseConfig struct {
	driverName      string
	dataSourceName  string
	tableName       string
	batchSize       int
	batchInterval   time.Duration
	maxConnLifetime time.Duration
	maxOpenConns    int
	maxIdleConns    int
	retryDelay      time.Duration
}

// NewDatabaseConfig creates a new DatabaseConfig with validation.
func NewDatabaseConfig(driver, dsn, table string, opts ...DatabaseConfigOption) (*DatabaseConfig, error) {
	if driver == "" {
		return nil, &ConfigError{Field: "driver", Msg: "driver cannot be empty"}
	}
	if dsn == "" {
		return nil, &ConfigError{Field: "dsn", Msg: "data source name cannot be empty"}
	}
	if table == "" {
		return nil, &ConfigError{Field: "tableName", Msg: "table name cannot be empty"}
	}
	cfg := &DatabaseConfig{
		driverName:      driver,
		dataSourceName:  dsn,
		tableName:       table,
		batchSize:       DefaultBatchSize,
		batchInterval:   DefaultBatchInterval,
		maxConnLifetime: 0,
		maxOpenConns:    DefaultMaxOpenConns,
		maxIdleConns:    DefaultMaxIdleConns,
		retryDelay:      DefaultRetryDelay,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg, nil
}

// DatabaseConfigOption is a functional option for DatabaseConfig.
type DatabaseConfigOption func(*DatabaseConfig)

// WithBatchSize sets the batch size for database inserts.
func WithBatchSize(n int) DatabaseConfigOption {
	return func(cfg *DatabaseConfig) { cfg.batchSize = n }
}

// WithBatchInterval sets the flush interval for batches.
func WithBatchInterval(d time.Duration) DatabaseConfigOption {
	return func(cfg *DatabaseConfig) { cfg.batchInterval = d }
}

// WithMaxConnLifetime sets the maximum connection lifetime.
func WithMaxConnLifetime(d time.Duration) DatabaseConfigOption {
	return func(cfg *DatabaseConfig) { cfg.maxConnLifetime = d }
}

// WithMaxOpenConns sets the maximum number of open connections.
func WithMaxOpenConns(n int) DatabaseConfigOption {
	return func(cfg *DatabaseConfig) { cfg.maxOpenConns = n }
}

// WithMaxIdleConns sets the maximum number of idle connections.
func WithMaxIdleConns(n int) DatabaseConfigOption {
	return func(cfg *DatabaseConfig) { cfg.maxIdleConns = n }
}

// WithRetryDelay sets the delay between retries.
func WithRetryDelay(d time.Duration) DatabaseConfigOption {
	return func(cfg *DatabaseConfig) { cfg.retryDelay = d }
}

// Getter methods for DatabaseConfig
func (c *DatabaseConfig) DriverName() string             { return c.driverName }
func (c *DatabaseConfig) DataSourceName() string         { return c.dataSourceName }
func (c *DatabaseConfig) TableName() string              { return c.tableName }
func (c *DatabaseConfig) BatchSize() int                 { return c.batchSize }
func (c *DatabaseConfig) BatchInterval() time.Duration   { return c.batchInterval }
func (c *DatabaseConfig) MaxConnLifetime() time.Duration { return c.maxConnLifetime }
func (c *DatabaseConfig) MaxOpenConns() int              { return c.maxOpenConns }
func (c *DatabaseConfig) MaxIdleConns() int              { return c.maxIdleConns }
func (c *DatabaseConfig) RetryDelay() time.Duration      { return c.retryDelay }

// SyslogConfig holds configuration for syslog output.
type SyslogConfig struct {
	network       string
	address       string
	tag           string
	facility      int
	reconnect     bool
	retryDelay    time.Duration
	tlsSkipVerify bool
	staticHost    string
	secure        bool
	rfc5424       bool
	bufferSize    int
	timeZone      string
	jsonInMessage bool
}

// NewSyslogConfig creates a new SyslogConfig with validation.
func NewSyslogConfig(network, address string, opts ...SyslogConfigOption) (*SyslogConfig, error) {
	if network == "" {
		return nil, &ConfigError{Field: "network", Msg: "network cannot be empty"}
	}
	if address == "" {
		return nil, &ConfigError{Field: "address", Msg: "address cannot be empty"}
	}
	cfg := &SyslogConfig{
		network:       network,
		address:       address,
		tag:           DefaultSyslogTag,
		facility:      1, // user-level messages
		reconnect:     true,
		retryDelay:    DefaultRetryDelay,
		tlsSkipVerify: false,
		secure:        false,
		rfc5424:       false,
		bufferSize:    1000,
		timeZone:      "UTC",
		jsonInMessage: false,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg, nil
}

// SyslogConfigOption is a functional option for SyslogConfig.
type SyslogConfigOption func(*SyslogConfig)

// WithSyslogTag sets the syslog tag.
func WithSyslogTag(tag string) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.tag = tag }
}

// WithSyslogFacility sets the syslog facility.
func WithSyslogFacility(f int) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.facility = f }
}

// WithSyslogReconnect enables or disables automatic reconnection.
func WithSyslogReconnect(reconnect bool) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.reconnect = reconnect }
}

// WithSyslogRetryDelay sets the delay between reconnection attempts.
func WithSyslogRetryDelay(d time.Duration) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.retryDelay = d }
}

// WithTLSSkipVerify sets whether to skip TLS certificate verification.
func WithTLSSkipVerify(skip bool) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.tlsSkipVerify = skip }
}

// WithStaticHost sets a static hostname (overrides system hostname).
func WithStaticHost(host string) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.staticHost = host }
}

// WithSecure enables TLS.
func WithSecure(secure bool) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.secure = secure }
}

// WithRFC5424 enables RFC5424 protocol.
func WithRFC5424(rfc bool) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.rfc5424 = rfc }
}

// WithBufferSize sets the buffer size.
func WithBufferSize(size int) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.bufferSize = size }
}

// WithTimeZone sets the timezone for timestamps.
func WithTimeZone(tz string) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.timeZone = tz }
}

// WithJSONInMessage enables JSON in message field.
func WithJSONInMessage(json bool) SyslogConfigOption {
	return func(cfg *SyslogConfig) { cfg.jsonInMessage = json }
}

// Getter methods for SyslogConfig
func (c *SyslogConfig) Network() string           { return c.network }
func (c *SyslogConfig) Address() string           { return c.address }
func (c *SyslogConfig) Tag() string               { return c.tag }
func (c *SyslogConfig) Facility() int             { return c.facility }
func (c *SyslogConfig) Reconnect() bool           { return c.reconnect }
func (c *SyslogConfig) RetryDelay() time.Duration { return c.retryDelay }
func (c *SyslogConfig) TLSSkipVerify() bool       { return c.tlsSkipVerify }
func (c *SyslogConfig) StaticHost() string        { return c.staticHost }
func (c *SyslogConfig) Secure() bool              { return c.secure }
func (c *SyslogConfig) RFC5424() bool             { return c.rfc5424 }
func (c *SyslogConfig) BufferSize() int           { return c.bufferSize }
func (c *SyslogConfig) TimeZone() string          { return c.timeZone }
func (c *SyslogConfig) JSONInMessage() bool       { return c.jsonInMessage }

// SamplingConfig holds configuration for log sampling.
type SamplingConfig struct {
	enabled    bool
	initial    int
	thereafter int
	window     time.Duration
}

// NewSamplingConfig creates a new SamplingConfig with validation.
func NewSamplingConfig(enabled bool, initial, thereafter int, window time.Duration) (*SamplingConfig, error) {
	if initial <= 0 {
		initial = 100
	}
	if thereafter <= 0 {
		thereafter = 10
	}
	if window <= 0 {
		window = time.Second
	}
	return &SamplingConfig{
		enabled:    enabled,
		initial:    initial,
		thereafter: thereafter,
		window:     window,
	}, nil
}

// Getter methods for SamplingConfig
func (c *SamplingConfig) Enabled() bool         { return c.enabled }
func (c *SamplingConfig) Initial() int          { return c.initial }
func (c *SamplingConfig) Thereafter() int       { return c.thereafter }
func (c *SamplingConfig) Window() time.Duration { return c.window }

// ConfigError represents a configuration error.
type ConfigError struct {
	Field string
	Msg   string
}

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Msg
}

// MustNewFileConfig creates a FileConfig with default options and panics on error.
func MustNewFileConfig(path string) *FileConfig {
	cfg, err := NewFileConfig(path)
	if err != nil {
		panic(err)
	}
	return cfg
}

// MustNewDatabaseConfig creates a DatabaseConfig and panics on error.
func MustNewDatabaseConfig(driver, dsn, table string) *DatabaseConfig {
	cfg, err := NewDatabaseConfig(driver, dsn, table)
	if err != nil {
		panic(err)
	}
	return cfg
}

// MustNewSyslogConfig creates a SyslogConfig and panics on error.
func MustNewSyslogConfig(network, address string) *SyslogConfig {
	cfg, err := NewSyslogConfig(network, address)
	if err != nil {
		panic(err)
	}
	return cfg
}

// MustNewSamplingConfig creates a SamplingConfig and panics on error.
func MustNewSamplingConfig(enabled bool, initial, thereafter int, window time.Duration) *SamplingConfig {
	cfg, err := NewSamplingConfig(enabled, initial, thereafter, window)
	if err != nil {
		panic(err)
	}
	return cfg
}
