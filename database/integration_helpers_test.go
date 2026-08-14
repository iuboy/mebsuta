//go:build integration

package database

import (
	"gorm.io/driver/gaussdb"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func openGormDB(driver, dsn string) (*gorm.DB, error) {
	switch driver {
	case "opengauss":
		return gorm.Open(gaussdb.Open(dsn), &gorm.Config{})
	default: // "postgres"
		return gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}
}
