module github.com/iuboy/mebsuta

go 1.26.10

require (
	github.com/google/uuid v1.6.0
	github.com/iuboy/mbta-go v0.1.0-0
	github.com/oklog/ulid/v2 v2.1.2
	github.com/prometheus/client_golang v1.25.0
	github.com/prometheus/client_model v0.6.3
	github.com/stretchr/testify v1.12.1
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.23.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.47.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.47.0
	go.opentelemetry.io/otel/log v1.47.0
	go.opentelemetry.io/otel/metric v1.47.0
	go.opentelemetry.io/otel/sdk v1.47.0
	go.opentelemetry.io/otel/sdk/log v1.47.0
	go.opentelemetry.io/otel/sdk/metric v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
	go.opentelemetry.io/proto/slim/otlp v1.11.1
	google.golang.org/protobuf v1.36.12
	gorm.io/driver/gaussdb v0.1.0
	gorm.io/driver/postgres v1.6.3
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.31.2
)

require (
	github.com/HuaweiCloudDeveloper/gaussdb-go v1.0.0-rc1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/emmansun/gmsm v0.45.4 // indirect
	github.com/fxamacker/cbor/v2 v2.10.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.34.0 // indirect
	github.com/iuboy/pollux-go v0.1.2-3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.13.0 // indirect
	github.com/jackc/puddle/v2 v2.2.4 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/klauspost/compress v1.20.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.53 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pandatix/go-abnf v0.5.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.34 // indirect
	github.com/prometheus/common v0.74.0 // indirect
	github.com/prometheus/procfs v0.23.0 // indirect
	github.com/quic-go/quic-go v0.65.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.2 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.47.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.1 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261118221215-c8830f628b3f // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261118221215-c8830f628b3f // indirect
	google.golang.org/grpc v1.85.0 // indirect
)

// iuboy 世系防倒退守卫（CHANGELOG 0.1.0-1）：模块代理缓存已删除的旧世系
// 标签（mbta-go v0.7.0、pollux-go v0.5.2）且永不过期，go mod tidy/-u 会
// 把它们当作"最新"误升；replace 钉住正确世系，tidy 不再回退。replace 对
// 消费方不可见，仅保护本仓构建。
replace github.com/iuboy/mbta-go => github.com/iuboy/mbta-go v0.1.0-0

replace github.com/iuboy/pollux-go => github.com/iuboy/pollux-go v0.1.2-3
