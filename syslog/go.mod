module github.com/iuboy/mebsuta/syslog

go 1.26.0

require (
	github.com/iuboy/mebsuta v0.0.0
	github.com/iuboy/mebsuta/audit v0.0.0
)

replace (
	github.com/iuboy/mebsuta => ../
	github.com/iuboy/mebsuta/audit => ../audit
)
