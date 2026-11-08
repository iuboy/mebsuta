# Versioning

Mebsuta 的版本号**恒为 `v0.1.<patch>-<rev>`**（2026-11-08 起，世系重置）。

## Module

Go module path: `github.com/iuboy/mebsuta`

## 版本格式

```text
v0.1.<patch>-<rev>
```

- **只有 patch（`0.1.x` 的 x）与 rev（`-0` 的数字）两位会递增**；major/minor
  （`0.1`）不再演进——包括破坏性变更在内的一切变更都只走 patch/rev 节奏。
- **默认进行破坏性变更，无兼容要求**：除非维护者在变更指令中显式要求保持
  兼容，API 的破坏性调整不需升 minor、不需兼容别名、不需迁移期——调用方
  随版本更新同步修正。破坏性内容仍在 CHANGELOG「破坏性变更」小节逐条列出
  （知情记录，而非兼容承诺）。
- 同一 patch 内的修正递增 rev（`v0.1.2-0` → `v0.1.2-1`）；新变更发布递增
  patch 并将 rev 复位 0。
- 目标版本号已被占用（打标/推送时发现重复）即视为冲突：rev 向后延续至下一
  个未占用值（`v0.1.2-x` → `v0.1.2-x+1` …），已发布版本号永不重用或覆盖。

## 发版流程

1. CHANGELOG 定版（新变更 patch 递增、rev 复位 0；同 patch 热修递增 rev）。
2. 打 `v0.1.x-<rev>` 标签推送 → release.yml 出 Release。

## Legacy Tags（已移除）

旧世系标签 `v0.1.0`–`v0.8.0` 及 `latest` 已从仓库（本地与远程）移除，
其变更条目保留在 CHANGELOG 末尾仅作历史记录。旧世系（含 monorepo 拆分前
`go/` 子目录 import path 时代）与现行版本无兼容关系。
