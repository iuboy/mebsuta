//go:build integration

package database

import (
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func openGormDB(driver, dsn string) (*gorm.DB, error) {
	switch driver {
	case "mysql":
		return gorm.Open(mysql.Open(dsn), &gorm.Config{})
	case "postgres":
		return gorm.Open(postgres.Open(dsn), &gorm.Config{})
	default:
		return nil, nil
	}
}
