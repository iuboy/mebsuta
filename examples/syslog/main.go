// syslog: send logs to a remote syslog server
package main

import (
	"log/slog"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/syslog"
)

func main() {
	syslogH, err := syslog.NewHandler(syslog.Config{
		Network:  "tcp",
		Address:  "localhost:514",
		Tag:      "myapp",
		Facility: 1,
	})
	if err != nil {
		panic(err)
	}

	logger, err := mebsuta.New(
		mebsuta.UseStdout(mebsuta.StdoutConfig{}),
		mebsuta.WithHandler(syslogH),
	)
	if err != nil {
		panic(syslogH.Close())
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("application started")
	slog.Error("simulated error", "code", 500)
}
