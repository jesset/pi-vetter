# 证据不完整时 Verdict 封顶 ASK（fail-closed）

任何已启用的 Scanner 未完成（超时、错误、API 配额耗尽）时，该包的 Verdict 最高只能是 ASK，永不静默 ALLOW。证据清单中显式列出未完成项。

**Why**：外部情报缺失恰是攻击窗口——新发布的恶意版本在一段时间内不在任何漏洞/恶意库中；静默放行等于把"扫描器故障"当作"安全证明"。

**Considered Options**：仅标注不影响判定（被拒——违背 fail-closed）；不完整直接 DENY（被拒——常态化的 Scanner 故障会让工具不可用，且 DENY 语义留给"明确恶意证据"）。

**Consequences**：网络依赖型 Scanner（osv、virustotal、socket）故障或配额尽时，用户会看到 ASK 而非 ALLOW——这是刻意行为。Socket 免费层配额极低（实测约 5 次查询/小时），故默认禁用，由用户显式开启并承担常态 ASK 的代价。
