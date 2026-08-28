# 批准后用 `pi install npm:<pkg>@<version>` 安装，而非 `pi update`

用户批准安装某候选版本后，扩展以子进程执行 `pi install npm:<pkg>@<version>`（精确版本 spec），不使用 `pi update`。

**Why**：pi 源码事实（`package-manager.ts`）——`pi update` 不支持指定目标版本，且带精确版本的 spec 会被 `pi update --extensions` 跳过；`pi install` 是安装指定版本并改写 settings 条目的唯一正规入口。因此 `pi install <pkg>@<ver>` 一步同时完成"安装评估过的那个版本"与"钉定该版本使未来的批量更新不再触碰它"（TOCTOU 缓解的一部分：配合安装前 Integrity Check）。

**Surprising**：直觉上"更新工具应该调 update"，未来读者看到 install 会以为是 bug——本 ADR 说明这是对 pi 行为的刻意适配。
