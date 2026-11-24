# mebsuta — AI 编码代理要点

面向 AI 编码代理的项目约定。细节链接 [docs/CONTRIBUTING.md](./docs/CONTRIBUTING.md)
与 [docs/VERSIONING.md](./docs/VERSIONING.md)。

## 版本与破坏性策略（默认裁决，2026-11-08 起）

- **默认进行破坏性更改，无兼容要求**：除非用户/维护者在当前指令中显式要求
  保持兼容，API 的破坏性调整不需兼容别名、不需迁移期、不需升 minor——
  调用方随版本更新同步修正。
- **版本号恒为 `v0.1.<patch>-<rev>`**：只有 patch 与 rev 递增（0 与 1 两位
  永不演进）。破坏性变更同样只递增 patch/rev，禁止自行升 minor/major。
- 破坏性内容 MUST 在 CHANGELOG 对应小节逐条列出（知情记录，非兼容承诺）；
  发版在 CHANGELOG 定版并打 `v0.1.x-<rev>` 标签。
- 目标版本号已被占用即视为重复：rev 向后延续至下一个未占用值，已发布版本
  号永不重用或覆盖。

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **mebsute** (2202 symbols, 8122 relationships, 191 execution flows).

> Index stale? Run `node .gitnexus/run.cjs analyze --index-only` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? Bootstrap with `npx`, `bunx`, or `pnpm dlx` — e.g. `bunx gitnexus@latest analyze` (npm 11 npx crash; #1939).

## Always Do

- **MUST run impact before editing.** Use `impact({target: "symbolName", direction: "upstream"})` or `node .gitnexus/run.cjs impact "symbolName" --direction upstream --repo .`; report callers, processes, and risk. Never substitute grep for graph analysis.
- **MUST analyze graph changes before committing.** Use `detect_changes({scope: "all"})` (MCP) or `node .gitnexus/run.cjs detect-changes --scope all --repo .` (CLI fallback). `partial: true` or `truncated: true` is not a clean check — a zero means unseen, not unaffected; re-run it. For regression review: `detect_changes({scope: "compare", base_ref: "dev"})` or `node .gitnexus/run.cjs detect-changes --scope compare --base-ref "dev" --repo .`.
- MUST warn on HIGH/CRITICAL `risk` pre-edit; never use `riskSharedAxes` to waive a HIGH/CRITICAL `risk` warning. Compare File/symbol: MCP File omits axes; Graph-RAG expands File.
- **MUST treat `risk: UNKNOWN` as unresolved, not as low.** An empty caller set is not evidence the symbol is unused — it can also mean the callers are not resolvable by the index (plain-object property access, dynamic dispatch, cross-language calls). `impact` pairs `UNKNOWN` with a `riskNote` saying so. Confirm with a text search before treating the symbol as safe to change or delete; do not proceed on the strength of a zero.
- **MUST use `query({search_query: "concept"})` for concepts/flows, `context({name: "symbolName"})` for a named symbol, or `impact` for blast radius, on read-only callers, dependencies, imports, or execution flow.** Graph first; text search only for empty/`UNKNOWN`/literals.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method before MCP/CLI impact analysis.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis, and never read `UNKNOWN` as an all-clear — it means the walk could not answer, which is the one verdict that requires confirming by other means.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit before MCP/CLI graph change analysis.

## Resources

| Resource | Use for |
| --- | --- |
| `gitnexus://repo/mebsute/context` | Codebase overview, check index freshness |
| `gitnexus://repo/mebsute/clusters` | All functional areas |
| `gitnexus://repo/mebsute/processes` | All execution flows |
| `gitnexus://repo/mebsute/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
| --- | --- |
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
