//go:build integration
// +build integration

package mebsuta_test

// 此文件仅用于添加集成测试构建标签
//
// 运行集成测试:
//   go test ./... -tags=integration
//
// 跳过集成测试:
//   go test ./... -short
//
// 集成测试使用testcontainers运行真实的服务(如MySQL)
