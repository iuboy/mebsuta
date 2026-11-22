package database

import (
	"database/sql"
	"fmt"
	"time"

	"gorm.io/driver/gaussdb"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// PoolConfig 是 OpenGorm 调用方共享的连接池形态。
// 零值字段保持 database/sql 默认（生命周期不限、驱动
// 默认值），与日志 handler 对自身池字段的
// 语义文档保持一致。
type PoolConfig struct {
	MaxIdleConns    int
	MaxOpenConns    int
	MaxConnLifetime time.Duration
}

// OpenGorm 为受支持的驱动打开带连接池的 gorm 会话。它是
// 日志 handler、span/metric exporter 与 telemetry database 后端
// 共享的唯一拨号路径，驱动选择、静默 gorm 日志与错误脱敏
// 因此在所有调用点行为一致。返回的会话归调用方所有：
// 用完后经返回的 *sql.DB 关闭。
func OpenGorm(driver, dsn string, pool PoolConfig) (*gorm.DB, *sql.DB, error) {
	// openGauss 使用 GaussDB GORM 驱动（gorm.io/driver/gaussdb）；
	// 它说的是 PostgreSQL 兼容协议，但 openGauss 特有的认证
	//（sha256）与错误码需要专属驱动。
	var dialector gorm.Dialector
	switch driver {
	case "opengauss":
		dialector = gaussdb.Open(dsn)
	case "postgres":
		dialector = postgres.Open(dsn)
	default:
		return nil, nil, fmt.Errorf("database: unsupported driver %q (supported: postgres, opengauss)", driver)
	}

	// gorm 自身的日志刻意静默——为什么这里绝不能留着
	// 默认 logger，见 newGORMConfig。
	gdb, err := gorm.Open(dialector, newGORMConfig())
	if err != nil {
		return nil, nil, fmt.Errorf("database: connect %s database: %s", driver, sanitizeDBError(err))
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		// gorm.Open 成功但 DB() 失败——关闭底层
		// 连接。
		closeSQLDB(gdb)
		return nil, nil, fmt.Errorf("database: get database connection: %w", err)
	}

	if pool.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(pool.MaxIdleConns)
	}
	if pool.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(pool.MaxOpenConns)
	}
	if pool.MaxConnLifetime > 0 {
		sqlDB.SetConnMaxLifetime(pool.MaxConnLifetime)
	}
	return gdb, sqlDB, nil
}
