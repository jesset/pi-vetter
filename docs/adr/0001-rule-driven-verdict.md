# Verdict 由规则映射驱动，风险分仅作展示

判定 Verdict（ALLOW/ASK/DENY）采用规则映射：DENY 规则命中 → DENY；ASK 规则命中 → ASK；否则 ALLOW。加权分数只作辅助展示，不参与判定。

**Why**：项目定位是 evidence-driven 评估器——"为什么是 ASK"必须能指向具体证据（如"新增 postinstall"），而分数阈值（"72 分所以 ASK"）不可解释；且外部调研中两套候选评分模型（加法扣分制与五维加权制）互不一致，均无实证权重依据。

**Considered Options**：加权分数阈值驱动（被拒，理由如上）；混合制中曾考虑"分数可否决规则"（被拒——两套机制会产生矛盾的 Verdict，用户无所适从）。

**Consequences**：新增风险信号 = 新增规则（带开关与严重级别），而非调权重。分数权重仍是配置项，但其变化永远不会改变 Verdict。
