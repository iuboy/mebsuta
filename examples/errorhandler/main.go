// errorhandler: custom error handling for internal handler errors
package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/filerotate"
)

func main() {
	dir, _ := os.MkdirTemp("", "mebsuta-err")
	defer os.RemoveAll(dir)

	logger, err := mebsuta.New(
		mebsuta.UseFile(filerotate.Config{
			Path:       filepath.Join(dir, "app.log"),
			MaxSizeMB:  1,
			MaxBackups: 3,
		}, mebsuta.FileConfig{}),
		mebsuta.WithErrorHandler(func(he *mebsuta.HandlerError) {
			fmt.Fprintf(os.Stderr, "[ERROR] component=%s op=%s err=%v dropped=%d\n",
				he.Component, he.Operation, he.Err, he.Dropped)
		}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("normal log", "status", "ok")
}
