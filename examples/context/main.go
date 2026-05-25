// context: extract fields from context.Context into log records
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/iuboy/mebsuta"
)

type contextKey string

const requestIDKey contextKey = "request_id"

func main() {
	logger, err := mebsuta.New(
		mebsuta.UseContextExtractor(func(ctx context.Context) []slog.Attr {
			if id, ok := ctx.Value(requestIDKey).(string); ok {
				return []slog.Attr{slog.String("request_id", id)}
			}
			return nil
		}),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	ctx := context.WithValue(context.Background(), requestIDKey, "req-456")
	slog.InfoContext(ctx, "request received", "path", "/api/users")

	slog.Info("no context", "msg", "request_id will be absent")

	_ = os.Stdout.Sync()
}
