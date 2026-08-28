# pi-vetter

Pi 编码代理扩展的安全扫描/评估器：在安装或更新一个 Pi 扩展包之前，对候选版本做多路安全评估，产出证据驱动的判定（ALLOW/ASK/DENY），由用户选择性地完成安装。

## Language

### 评估对象

**Candidate（候选版本）**:
待评估的 `package@version`。更新场景取已装包在 registry 上的最新版；安装场景由用户给定的 spec 解析（缺版本时取最新）。
_Avoid_: 目标包、新版本、package update

**Baseline（基线版本）**:
Candidate 的对照物，即更新场景中已安装的版本（diff 以 registry 上该版本的干净 tarball 为基准）。安装场景无基线。
_Avoid_: 旧版本、当前版本

### 评估过程

**Vet（审查）**:
本项目的核心动作：对一个或多个 Candidate 执行完整评估。`/vet` 只审查不安装，`/vet-install` 审查后经用户选择执行安装。
_Avoid_: safe update（暗示安全保证）、scan（只是 Vet 的一部分）

**Scanner（扫描器）**:
单一证据来源的封装（如 osv、provenance、static、diff、metadata、virustotal、socket），可独立启用/禁用。
_Avoid_: engine、checker、analyzer

**Layer（层）**:
Scanner 的成本与来源分层：L0 registry 元数据、L1 免费外部情报、L2 本地静态分析、L3 需密钥的外部引擎。
_Avoid_: level、tier

**Evaluation（评估）**:
对一个 Candidate 的全部已启用 Scanner 的执行与汇总，产出 Evaluation Report。
_Avoid_: report run、audit run

### 判定

**Evidence（证据）**:
Scanner 产出的原子事实，状态为 pass / fail / info / skipped / incomplete。
_Avoid_: check、result

**Incomplete Evidence（证据不完整）**:
已启用的 Scanner 未完成（超时、错误、配额耗尽）。是 fail-closed 的触发条件。
_Avoid_: scan failure、missing data

**Finding（发现）**:
命中某条规则的风险性判定，携带规则 ID 与严重级别。
_Avoid_: alert、issue、detection

**Rule（规则）**:
Evidence 到 Verdict 影响的映射，分 DENY 规则（明确恶意/矛盾证据）与 ASK 规则（需人工决策的信号），可逐条开关。
_Avoid_: policy、check

**Verdict（判定）**:
单包评估结论：ALLOW（未发现风险信号）/ ASK（需用户决策）/ DENY（存在明确恶意或矛盾证据）。Verdict 只描述"未发现风险"，不承诺安全。
_Avoid_: SAFE/UNSAFE、trust level（措辞）、score threshold

**Cap（封顶）**:
Verdict 不得高于某级别的约束。证据不完整时封顶 ASK（fail-closed）。
_Avoid_: downgrade、block

**Risk Score（风险分）**:
纯辅助展示的聚合数值，不参与 Verdict 判定。
_Avoid_: trust score、security score

### 呈现

**Progress（进度）**:
Vet 过程中的临时状态呈现，只回答"进行到哪了"，不承载 Verdict；命令结束（含中止）即清除，不留任何记录。
_Avoid_: status bar、spinner、进度条

**Report（报告）**:
Vet 全部完成后一次性输出的持久化逐包结论记录，按 Verdict 严重度排序，是 Verdict 与 Evidence 的唯一呈现载体。
_Avoid_: 逐包流式输出、scan output

### 执行

**Approval（批准）**:
用户在 `/vet-install` 中选择安装某 Candidate 的动作。
_Avoid_: confirm、accept

**Pinned Spec（钉定规格）**:
带精确版本的 npm spec（`npm:<pkg>@<version>`）。Pi 的包更新会跳过被钉定的条目。
_Avoid_: lock、freeze

**Integrity Check（完整性比对）**:
批准之后、安装之前，registry 完整性值与评估时记录值的比对，防止"扫描物 ≠ 安装物"（TOCTOU）。
_Avoid_: hash check、checksum verify

**Lifecycle Script Warning（生命周期脚本警告）**:
固定的提示：批准安装即意味着执行该包的 install 脚本。Pi 安装不带 `--ignore-scripts`，此风险无法由本工具消除，只能明示。
_Avoid_: postinstall warning
