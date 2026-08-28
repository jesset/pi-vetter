# 批准后用 `pi install npm:<pkg>@<version>` 安装；默认不保留 pin

用户批准安装某候选版本后，扩展以子进程执行 `pi install npm:<pkg>@<version>`（Pi 中升降级到指定版本的唯一正规入口，保证单次安装的精确性，配合安装前 Integrity Check 构成 TOCTOU 防护）。**默认在安装成功后把 settings 条目还原为非 pin 的 `npm:<pkg>`**（`install.pinOnInstall: false`），安装结果中明示可手动 pin 的命令；配置为 `true` 时保留 `pi install` 写入的 pinned spec（原始行为）。

**Why（2026-08-28 修订，issue #16）**：原始决策把 pin（"从此退出更新通道"）当作安装的隐式副作用，混淆了两个决定——用户批准的是"装这个版本"，不是"永久冻结"。pin 会静默冻结未来的安全修复，卸载 pi-vetter 后残留 pin 的安全状态劣于不装；且修订前 resolveTargets 连 pinned 包也跳过，评估器自己也产生盲区。修订后：单次安装的精确性由 `pi install <pkg>@<ver>` 本身保证，与持久 pin 无关；更新策略是用户的显式决定（评估器给出证据与建议，不垄断通道）；pinned 包照常纳入评估并在报告标注 baseline is pinned。

**Considered Options**：保留 pin 副作用（被拒，上述）；彻底去掉 `/vet-install` 只输出建议命令（被拒——失去安装时刻的 TOCTOU 预检闭环）。

**Consequences**：默认路径下已批准的包此后随 `pi update --extensions` 正常流动（每轮更新可再经 `/vet` 评估）；想锁定的用户按安装结果中的提示自行执行 pin 命令，或改配置。settings 还原是 best-effort（失败不影响已装版本）。
