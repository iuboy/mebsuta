//go:build integration

package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func openGormDB(dsn string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}
