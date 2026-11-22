# 全局状态地图（单例面）

> 原则（2026-11-22 裁决）：**不新增自有全局单例**。mebsuta 的单例面
> 完全站在两处生态标准上；调用方已能用这两把全局句柄触达全部门面。
> 出现"必须全局可达且无生态标准可骑"的能力时再议——当前不存在。

## 生态标准单例（唯二）

| 全局 | 写入点 | 读取方 |
| --- | --- | --- |
| `slog.SetDefault` | `mebsuta.Init` | stdlib 全家（`slog.Info` 等）与 `mebsuta.Info/...` 便捷函数 |
| `otel.Set{Tracer,Meter,Logger}Provider` / `SetTextMapPropagator` / `SetErrorHandler` | `telemetry.Start`（`SetGlobal` 默认开；`SetGlobal=false` 完全不触碰，部署方自理） | otelgin/otelhttp 等中间件、`mebsuta.StartSpan/Counter/...` 门面 |

## 设施级包变量（无业务语义，不构成 API 面）

`sync.Pool` ×6（JSON 编码/属性映射/handler core）、`handlerSeq`、
`DefaultErrorHandler`（带锁可替换）、metric 门面 instrument 缓存
（sync.Map，按名——见 STYLE.md 安全纪律）、`defaultIDGen`（ULID）。

## 已知局限（知情记录）

- 覆盖告警（`telemetry.Start` 的 global-overwrite）只跟踪**本包**安装的
  TracerProvider——跨库对 otel 全局的安装不可见（otel 无"是否已设"公共
  API）。
- 测试隔离：`mebsutatest.ResetOTelGlobals()` 复位 otel 全局；使用覆盖
  告警的测试另需 `telemetry.ResetGlobalTracking()`（两包解耦以免测试环）。

## 反面清单（明确不做）

- 全局 `*Telemetry` / 全局 logger 句柄——第二事实源，无增益
- 库内静默安装单例——Go 社区共识：库不装单例，应用侧用 `Init`
- 采样率热调（SDK sampler 构造期固定）——代次轮换模式见 README「热重载」
