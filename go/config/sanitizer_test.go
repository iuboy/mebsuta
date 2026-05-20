package config

import (
	"strings"
	"testing"
)

func TestDatabaseConfig_Sanitize(t *testing.T) {
	tests := []struct {
		name string
		cfg  *DatabaseConfig
		want []string // substrings that must appear
		skip []string // substrings that must NOT appear
	}{
		{
			name: "nil",
			cfg:  nil,
			want: nil,
		},
		{
			name: "mysql dsn masked",
			cfg: &DatabaseConfig{
				DriverName:     "mysql",
				DataSourceName: "root:s3cret@tcp(localhost:3306)/db",
				TableName:      "logs",
				BatchSize:      100,
				MaxOpenConns:   10,
			},
			want: []string{"DriverName=mysql", "****", "TableName=logs"},
			skip: []string{"s3cret"},
		},
		{
			name: "postgres uri masked",
			cfg: &DatabaseConfig{
				DriverName:     "postgres",
				DataSourceName: "postgres://admin:p@ss@localhost:5432/db",
			},
			want: []string{"****"},
			skip: []string{"p@ss"},
		},
		{
			name: "password kv masked",
			cfg: &DatabaseConfig{
				DriverName:     "sqlserver",
				DataSourceName: "sqlserver://host?database=db&password=hunter2",
			},
			want: []string{"password=****"},
			skip: []string{"hunter2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.Sanitize()
			if tt.cfg == nil {
				if got != "" {
					t.Errorf("nil should return empty, got %q", got)
				}
				return
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in %q", w, got)
				}
			}
			for _, s := range tt.skip {
				if strings.Contains(got, s) {
					t.Errorf("should not contain %q in %q", s, got)
				}
			}
		})
	}
}

func TestFileConfig_Sanitize(t *testing.T) {
	if got := (*FileConfig)(nil).Sanitize(); got != "" {
		t.Errorf("nil should return empty, got %q", got)
	}
	got := (&FileConfig{Path: "/var/log/app.log", MaxSizeMB: 100, MaxBackups: 5}).Sanitize()
	if !strings.Contains(got, "/var/log/app.log") {
		t.Errorf("missing path in %q", got)
	}
}

func TestSyslogConfig_Sanitize(t *testing.T) {
	if got := (*SyslogConfig)(nil).Sanitize(); got != "" {
		t.Errorf("nil should return empty, got %q", got)
	}
	got := (&SyslogConfig{Network: "tcp", Address: "localhost:514", Tag: "app"}).Sanitize()
	if !strings.Contains(got, "localhost:514") {
		t.Errorf("missing address in %q", got)
	}
}

func TestSanitizeForLog(t *testing.T) {
	if got := SanitizeForLog(nil); got != "(nil)" {
		t.Errorf("nil should return (nil), got %q", got)
	}

	dbCfg := &DatabaseConfig{DriverName: "mysql"}
	if got := SanitizeForLog(dbCfg); !strings.Contains(got, "mysql") {
		t.Errorf("should dispatch to DatabaseConfig.Sanitize, got %q", got)
	}

	fileCfg := &FileConfig{Path: "/tmp/test.log"}
	if got := SanitizeForLog(fileCfg); !strings.Contains(got, "/tmp/test.log") {
		t.Errorf("should dispatch to FileConfig.Sanitize, got %q", got)
	}

	// Unknown type
	if got := SanitizeForLog("random"); !strings.Contains(got, "Config(") {
		t.Errorf("unknown type should return Config(...), got %q", got)
	}
}

func TestMaskPasswordInDSN_UnknownFormat(t *testing.T) {
	// Unknown formats must not leak any original content
	got := maskPasswordInDSN("short")
	if got != "(redacted)" {
		t.Errorf("short unknown DSN should be (redacted), got %q", got)
	}

	longDSN := "some_long_connection_string_that_exceeds_20_chars_easily"
	got = maskPasswordInDSN(longDSN)
	if got != "(redacted)" {
		t.Errorf("long unknown DSN should be (redacted), got %q", got)
	}
}
