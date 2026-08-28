# pi 扩展 API 事实清单（safe-update 扩展实现参考）

> 调查日期：2026-08-28。事实来源以一手来源为准：pi.dev 官方文档（/docs/latest）与 GitHub `earendil-works/pi` 仓库 `main` 分支源码（对应 npm 包 `@earendil-works/pi-coding-agent` 0.84.3，`engines: node >= 22.19.0`）。
> 另以两个已发布扩展的 npm tarball 源码作为实践佐证：`zmarketplace@0.7.8`、`@panzenbaby/pi-secure-extension@0.1.3`（后者与本项目场景几乎相同：审计后 install/update）。
> 所有 GitHub 源码链接基于 main 分支；行号可能随提交漂移。

---

## 1. 扩展入口与 API 面

### 1.1 入口签名

扩展导出**默认工厂函数**，接收 `ExtensionAPI`。同步或 async 均可；若返回 Promise，pi 会在 `session_start` / `resources_discover` 之前 await 它（异步初始化完成后才继续启动）。

```typescript
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) { /* ... */ }
// 或 export default async function (pi: ExtensionAPI) { /* ... */ }
```

- 来源：https://pi.dev/docs/latest/extensions （Writing an Extension / Async factory functions）
- 类型定义：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/extensions/types.ts

注意：官方文档明确警告**工厂函数可能在永不开启会话的调用中运行**（如 `pi --list-models`），不要在工厂里启动后台资源/进程/watcher/timer；应推迟到 `session_start` 或命令/工具回调中，并在 `session_shutdown` 清理。

### 1.2 `pi.registerCommand(name, options)`

TypeScript 精确签名（源码 types.ts）：

```typescript
registerCommand(name: string, options: Omit<RegisteredCommand, "name" | "sourceInfo">): void;

export interface RegisteredCommand {
  name: string;
  sourceInfo: SourceInfo;           // 由 pi 填充，注册时省略
  description?: string;
  getArgumentCompletions?: (argumentPrefix: string) =>
    AutocompleteItem[] | null | Promise<AutocompleteItem[] | null>;  // 可选参数自动补全
  handler: (args: string, ctx: ExtensionCommandContext) => Promise<void>;
}
```

关键事实：
- `handler` 的第一个参数 `args` 是**原始字符串**（`/cmd a b c` 的 `a b c` 整段），不是解析后的数组。需要自行 `args.trim().split(/\s+/)`。
- `name` 不带斜杠；注册后以 `/name` 调用。同名命令冲突时 pi 保留全部并加数字后缀（`/review:1`、`/review:2`，按加载顺序）。
- `ctx` 是 `ExtensionCommandContext`（见下），比普通事件 handler 的 `ExtensionContext` 多出会话控制方法——这些方法"只能在命令中使用，因为在事件 handler 里调用会死锁"（文档原话）。
- `pi.getCommands()` 可枚举当前会话全部可调用 slash 命令（扩展命令、prompt 模板、skill 命令），条目含 `sourceInfo`（`scope: "user" | "project" | "temporary"`、`origin: "package" | "top-level"`、`baseDir`），可作为判定命令归属的权威字段。
- 来源：https://pi.dev/docs/latest/extensions （pi.registerCommand / pi.getCommands）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/extensions/types.ts

### 1.3 `ExtensionCommandContext`（命令 handler 的 ctx）

= `ExtensionContext` 全部成员 + 以下命令专用方法：

- `getSystemPromptOptions()` — 系统提示构建输入（含上下文文件内容，视为敏感数据）
- `waitForIdle()` — 等待 agent 完全 settle（含自动重试、自动压缩重试、排队 follow-up）
- `newSession(options?)` / `fork(entryId, options?)` / `navigateTree(targetId, options?)` / `switchSession(sessionPath, options?)`
- `reload()` — 重新加载扩展/skills/prompts/themes/上下文文件

`ExtensionContext` 基础成员（事件 handler 通用）：`ui`、`mode`（`"tui" | "rpc" | "json" | "print"`）、`hasUI`、`cwd`、`sessionManager`（只读）、`modelRegistry`、`model`、`scopedModels`、`thinkingLevel`、`isIdle()`、`isProjectTrusted()`、`signal`、`abort()`、`hasPendingMessages()`、`shutdown()`、`getContextUsage()`、`compact(options?)`、`getSystemPrompt()`。

- 来源：https://pi.dev/docs/latest/extensions （ExtensionContext / ExtensionCommandContext 各节）

### 1.4 `pi.registerTool(definition)` / `pi.registerFlag(name, options)`

```typescript
// 工具（LLM 可调用）
pi.registerTool({
  name: "greet", label: "Greet", description: "...",
  parameters: Type.Object({ name: Type.String() }),   // typebox schema
  async execute(toolCallId, params, signal, onUpdate, ctx) {
    return { content: [{ type: "text", text: "..." }], details: {} };
  },
});

// CLI flag
registerFlag(name: string, options:
  | { description?: string; type: "boolean"; default?: boolean }
  | { description?: string; type: "string";  default?: string }
): void;
// 读取：pi.getFlag(name): boolean | string | undefined
```

- 来源：https://pi.dev/docs/latest/extensions （Quick Start / pi.registerFlag）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/extensions/types.ts

---

## 2. ctx.ui 交互能力

完整接口 `ExtensionUIContext`（源码 types.ts 133-293 行）已核对，关键签名：

```typescript
select(title: string, options: string[], opts?: ExtensionUIDialogOptions): Promise<string | undefined>;
confirm(title: string, message: string, opts?: ExtensionUIDialogOptions): Promise<boolean>;
input(title: string, placeholder?: string, opts?: ExtensionUIDialogOptions): Promise<string | undefined>;
editor(title: string, prefill?: string): Promise<string | undefined>;   // 多行编辑
notify(message: string, type?: "info" | "warning" | "error"): void;
custom<T>(factory: (tui, theme, keybindings, done: (result: T) => void) => Component,
          options?: { overlay?: boolean; overlayOptions?...; onHandle?... }): Promise<T>;
```

其中 `ExtensionUIDialogOptions = { signal?: AbortSignal; timeout?: number }`（超时自动关闭带倒计时；超时时 select/input 返回 `undefined`，confirm 返回 `false`）。

### 关键结论（对本项目最重要）

1. **`ctx.ui.select` 仅支持单选**。第二个参数是 `options: string[]`（纯字符串数组），返回单个字符串或 undefined。**没有内建 checkbox/多选**。官方类型定义与文档均无 multi-select。佐证：`@panzenbaby/pi-secure-extension` 的"update-all"对每个过期包逐个 `ctx.ui.confirm`，未做多选；`zmarketplace` 同样只用单选。
2. **没有内建表格/多列组件**。要展示表格或多列布局，只能用 `ctx.ui.custom()`（完全自定义 TUI 组件，接收 tui/theme/keybindings/done，临时接管编辑器区域，支持 overlay 浮层模式）或 `ctx.ui.setWidget(key, factory, { placement })`（编辑器上/下方持久组件，接受 `(tui, theme) => Component` 工厂）。`@earendil-works/pi-tui` 提供 `Box`、`Text`、`Markdown`、`SelectList`、`SettingsList`、`BorderedLoader` 等基础组件，可自由拼装。
3. **模式守卫**：`ctx.mode === "tui"` 才能用 `custom()`、组件工厂、终端原始输入；`ctx.hasUI`（TUI 与 RPC 为 true）守卫 dialog 与 notify/setStatus/setWidget；`-p`（print）与 `--mode json` 下 UI 方法为 no-op。RPC 模式下 `custom()` 返回 undefined。
4. 其余可用：`setStatus(key, text)`（页脚状态）、`setWidget`、`setWorkingMessage/setWorkingVisible/setWorkingIndicator`（流式加载指示）、`setEditorText/getEditorText`、`setTheme`、`ctx.ui.theme`（当前主题的 `fg()/bold()` 等）。
5. `ui_prompt_start`/`ui_prompt_end` 事件会在这些阻塞式 UI 周围触发（host 集成可用）。

- 来源：https://pi.dev/docs/latest/extensions （Custom UI / Dialogs / Widgets / Custom Components / Mode Behavior 各节）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/extensions/types.ts
- 组件 pattern 参考：https://pi.dev/docs/latest/tui

---

## 3. pi.exec / 子进程

### 3.1 `pi.exec` 签名与实现

```typescript
pi.exec(command: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
// ExecOptions = { signal?: AbortSignal; timeout?: number; cwd?: string }
// ExecResult  = { stdout: string; stderr: string; code: number; killed: boolean }
```

实现（core/exec.ts）：`node:child_process.spawn`，**`shell: false`**（args 数组直传，不经 shell 解析），stdin ignore；超时/abort 时 SIGTERM，5 秒后 SIGKILL。扩展内也**可以直接使用 `node:child_process`**（pi-secure-extension 的 source-resolver 即用 `execFileSync`）。

- 来源：https://pi.dev/docs/latest/extensions （pi.exec）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/exec.ts

### 3.2 在扩展内 spawn `pi install/update` 子进程：可行性与并发风险

**可行性：已验证可行，且有现成先例。** `@panzenbaby/pi-secure-extension` 的做法（workflows.ts）：

```typescript
const piArgs = [action, source, ...(flags ?? [])];   // action = "install" | "update"
const execResult = await pi.exec("pi", piArgs, { cwd: ctx.cwd });
if (execResult.code === 0) { /* 成功 */ } else { /* 失败, 读 stderr */ }
```

它另外用 `pi.exec("pi", ["list"], { cwd: ctx.cwd })` 解析 stdout 拿包列表。

并发/锁相关的已确认事实：

1. **settings.json 写入有文件锁**：`FileSettingsStorage.withLock` 用 `proper-lockfile`（`lockfile.lockSync(path, { realpath: false })`），ELOCKED 时重试最多 10 次、每次自旋 20ms（packages/coding-agent/src/core/settings-manager.ts 213-280 行）。CLI 的 `pi install/remove/update` 与 TUI 内写 settings（`/settings`、`/trust` 等）都走这条锁路径，进程间互斥。**扩展若直接 `fs` 改写 settings.json 则绕过该锁**，与并发的 pi 写入存在丢更新风险（正确姿势见第 4 节）。
2. **npm 安装目录无跨进程锁**：包安装到固定目录 `~/.pi/agent/npm/`（一个 `package.json` + `node_modules`，见第 5/7 节），pi 源码中没有对该目录的进程级互斥；pi 只是把同一 scope 的批量更新合并为**一次** `npm install` 调用（`updateNpmBatch`）来减少竞态。两个 pi 进程并发对同一 npm root 执行 `npm install` 没有互斥保护（npm 自身亦无跨进程锁）。单进程内串行 spawn 子进程更新则无此问题。
3. **更新"自身正在运行"的扩展是安全的**：扩展代码在启动时已被 jiti 加载进内存，子进程更新磁盘上的 node_modules 不影响当前进程；新代码在 `/reload` 或下次启动 pi 时生效。
4. 子进程环境注意：`PI_OFFLINE=1` / `--offline` 会禁用包安装的网络操作；`pi update`（无交互）不做项目 trust 提示（仅使用已保存决策）；`--approve`/`--no-approve` 可一次性覆盖项目 trust。
5. 检测自己运行在 pi 内：环境变量 `PI_VERSION`（pi 设置）；`OMP_VERSION`、`CLAUDE_CODE` 等用于其它 agent（zmarketplace detectAgent 的做法）。

- 来源：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/settings-manager.ts ；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/package-manager.ts ；tarball `@panzenbaby/pi-secure-extension@0.1.3`（src/workflows.ts、src/commands.ts，https://github.com/Panzenbaby/pi-secure-extension ）；tarball `zmarketplace@0.7.8`（src/core/install.ts，https://github.com/zico20047/zmarketplace ）

---

## 4. settings.json 的 packages 格式与编程式读写

### 4.1 文件位置

| 作用域 | 路径 |
| --- | --- |
| 全局 | `~/.pi/agent/settings.json`（`getAgentDir()` = `$HOME/.pi/agent`） |
| 项目 | `<cwd>/.pi/settings.json`（`CONFIG_DIR_NAME` 默认 `".pi"`，可被 rebrand 覆盖，勿硬编码） |

项目相对路径相对于所在 settings 文件解析；项目 settings 覆盖全局（嵌套对象深合并；`packages` 属于数组字段，**项目条目与全局条目按"包身份"去重，project 胜出**，project 条目 `autoload:false` 时作为全局条目的 delta 叠加）。

- 来源：https://pi.dev/docs/latest/settings ；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/config.ts

### 4.2 packages 条目形状（精确 JSON）

`packages?: PackageSource[]`，元素为 string 或 object（源码 settings-manager.ts 83-91 行）：

```typescript
export type PackageSource =
  | string
  | { source: string; autoload?: boolean;
      extensions?: string[]; skills?: string[]; prompts?: string[]; themes?: string[] };
```

字符串形式：

```
npm:@scope/pkg@1.2.3     # 精确版本 → pinned
npm:pkg                  # 无版本 → 跟随 latest
npm:@scope/pkg@^1.0.0    # semver range（validRange 判定）→ 非 pinned（满足范围内更新）
git:github.com/user/repo@v1        # git: 前缀支持 shorthand（github.com/u/r、git@host:u/r）
https://github.com/user/repo@v1    # 协议 URL 可不带 git: 前缀
ssh://git@github.com/user/repo
/abs/path 或 ./rel/path   # 本地路径，不复制；相对 settings 文件所在目录解析
```

对象形式（过滤加载哪些资源；`!pattern` 排除、`+path` 强制包含、`-path` 强制排除、`[]` 全不加载、省略键=全加载）：

```json
{ "packages": [
    { "source": "npm:my-package",
      "extensions": ["extensions/*.ts", "!extensions/legacy.ts"],
      "skills": [], "prompts": ["prompts/review.md"], "themes": ["+themes/legacy.json"] }
] }
```

**出入提醒**：官方 settings 文档示例出现裸包名 `{"packages": ["pi-skills", "@org/my-extension"]}`（https://pi.dev/docs/latest/settings 与仓库 docs/settings.md 均如此），但按 main 分支源码 `parseSource`/`isLocalPath` 的实现，不带 `npm:` 前缀的字符串会落入 local 分支（被当作相对 settings 目录的本地路径，不存在时静默跳过）；测试套件里全部使用 `npm:` 前缀形式。**实现时一律用 `npm:` 前缀**，不要依赖裸名。（未能确认文档示例是否有历史遗留的裸名 fallback——源码中未找到。）

- 来源：https://pi.dev/docs/latest/settings ；https://pi.dev/docs/latest/packages （Package Sources / Package Filtering / Scope and Deduplication）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/settings-manager.ts ；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/package-manager.ts （parseSource，约 1446-1466 行）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/utils/paths.ts （isLocalPath）

### 4.3 扩展如何编程式读写 settings

三条路线（按推荐顺序）：

1. **公开 SDK 导入（当前 main 已可用）**：`@earendil-works/pi-coding-agent` 的 index.ts **公开导出** `SettingsManager`（含 `SettingsManager.create(cwd, agentDir?)` 静态方法与 `PackageSource` 类型）、`DefaultPackageManager`、`CONFIG_DIR_NAME`、`getAgentDir`、`SessionManager` 等。因此扩展可直接：
   ```typescript
   import { SettingsManager, getAgentDir } from "@earendil-works/pi-coding-agent";
   const sm = SettingsManager.create(process.cwd(), getAgentDir());
   // 读: sm.getPackages() / sm.getProjectSettings()
   // 写: sm.setPackages(next) / sm.setProjectPackages(next) —— 内部走 proper-lockfile + 字段级合并写盘
   await sm.flush();  // 等待写队列
   ```
   注意 `setPackages` 等方法标记字段级 modified 后经写队列异步落盘，并做"仅合并被修改字段"的读-改-写（persistScopedSettings），对并发友好。`assertProjectTrustedForWrite`：项目 scope 写入要求项目已 trust。
   - 来源：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/index.ts （导出清单）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/settings-manager.ts （create/save/persistScopedSettings/withLock）
   - 佐证：`@panzenbaby/pi-secure-extension` 通过 `import.meta.resolve("@mariozechner/pi-coding-agent")` 定位 dist 后动态 import 内部 `core/settings-manager.js` / `core/package-manager.js` / `config.js` 并调用 `SettingsManager.create(...)` 与 `new DefaultPackageManager({cwd, agentDir, settingsManager})`——证明扩展进程内构造这些管理器可用；但它走内部路径是旧版本（`@mariozechner/*` scope 时代）没有公开导出时的变通，**现在 index.ts 已公开导出，无需再挖内部路径**（其挖路径方式对 dist 布局强耦合，属脆弱做法）。
2. **spawn `pi install/remove/update` 子进程**：settings 的增删改由 CLI 完成（pi-secure-extension 的主路线）。
3. **直接 fs 读写 `~/.pi/agent/settings.json`**（zmarketplace 的只读做法）：绕过 pi 的文件锁，仅适合**只读**；写入则应改用路线 1/2。

---

## 5. 已安装包的元数据获取（枚举扩展与当前版本）

已确认的权威数据源（源码 DefaultPackageManager）：

1. **settings 数组（安装意图）**：`~/.pi/agent/settings.json` 与 `.pi/settings.json` 的 `packages`（string 或 `{source,...}`）。包身份判定：npm → `npm:<name>`（忽略版本）；git → `git:<host>/<path>`（忽略 ref）；local → 解析后的绝对路径。
2. **npm 安装目录（实际安装内容）**：
   - 用户 scope：`~/.pi/agent/npm/`，其中 `package.json` 为占位（`{"name":"pi-extensions","private":true}`）+ `.gitignore`（内容 `*\n!.gitignore\n`）；包实体在 **`~/.pi/agent/npm/node_modules/<pkg-name>/`**。
   - 项目 scope：`<cwd>/.pi/npm/node_modules/<pkg-name>/`。
   - **当前版本**：读 `<安装路径>/package.json` 的 `version` 字段（源码 `getInstalledNpmVersion` 即如此实现）。
   - 旧版本曾装到 npm 全局 root（`npm root -g`），源码保留 legacy 回退（`getNpmInstallPath` 在 managed 路径不存在时探测全局 root / pnpm 全局）。
3. **git 安装目录**：`~/.pi/agent/git/<host>/<path>/`（项目：`.pi/git/<host>/<path>/`）。
4. **临时安装（`pi -e`）**：`~/.pi/agent/tmp/extensions` 与 `getTemporaryDir("npm")`（scope=temporary 的 npm root），进程级临时目录，用后即弃。
5. **pi 内置版本比较逻辑**（可直接复用）：`installedNpmMatchesConfiguredVersion` = `semver.satisfies(installedVersion, range)`；`shouldUpdateNpmSource`/`npmHasAvailableUpdate` = `semver.gt(latest, installed)`，latest 通过 `npm view <spec> version --json`（遵循 settings 的 `npmCommand`）获取。
6. **`DefaultPackageManager.checkForAvailableUpdates()`**：公开导出，返回 `PackageUpdate[] { source, displayName, type, scope }`——已过滤掉 pinned 与 local 的、有新版本的包。这是"哪些包可更新"的最省事答案（pi-secure-extension 正在用）。
7. **`DefaultPackageManager.listConfiguredPackages()`**：返回 `ConfiguredPackage[] { source, scope, filtered, installedPath }`（含安装路径，object 条目标 filtered=true）。
8. **CLI 兜底**：`pi list` 输出人类可读格式（"User packages:" / "  <source> [（filtered)]" / 第二行缩进 4 空格的 installedPath；"Project packages:" 同构），pi-secure 用正则 `/^\s{2}\S/` 且排除 `/^\s{4}\S/` 解析。结构化场景优先用上面 6/7 的 API 而非解析 stdout。

- 来源：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/package-manager.ts （getManagedNpmInstallPath/getNpmInstallRoot/ensureNpmProject/getInstalledNpmVersion/checkForAvailableUpdates/listConfiguredPackages/getPackageIdentity）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/package-manager-cli.ts （list 输出格式）；tarball `zmarketplace@0.7.8` src/core/installed.ts（直接 fs 读 settings 的只读先例）；tarball `@panzenbaby/pi-secure-extension@0.1.3` src/commands.ts（checkForAvailableUpdates 用法与 `pi list` stdout 解析）

---

## 6. 扩展自身的存储/缓存约定

**没有官方强制的每扩展数据目录 API**（ExtensionAPI 上无 dataDir）。已确认的实践与事实：

1. **官方推荐的项目内配置路径**：文档在 ctx.cwd 一节给出模式——`join(ctx.cwd, CONFIG_DIR_NAME, "my-extension.json")`（即 `.pi/my-extension.json`），并要求读取前用 `ctx.isProjectTrusted()` 守卫（项目配置仅对受信项目生效）。
   - 来源：https://pi.dev/docs/latest/extensions （ctx.cwd）
2. **`@panzenbaby/pi-secure-extension` 的约定**：全局规则文件放在 **`~/.pi/agent/extensions/<ext-name>-audit-rules.md`**（与自动发现目录同址、加后缀命名，避免与"每个文件都是扩展"的自动加载冲突——注意：放在 `~/.pi/agent/extensions/` 下的 `.ts/.js` 会被当作扩展加载，所以它的数据文件用 `.md` 扩展名规避）；项目级规则沿目录向上找最近的 `.pi/` 下的 `extensions/<ext-name>-audit-rules.md`，且因可被不可信项目注入，读取前必须 confirm。默认规则打包在包内 `audit-rules/default.md`。
   - 来源：tarball `@panzenbaby/pi-secure-extension@0.1.3` src/config.ts（https://github.com/Panzenbaby/pi-secure-extension ）
3. **`zmarketplace` 的约定**：搜索/审计缓存**纯内存**（模块级变量，MAX 150 条 LRU 式淘汰），不做磁盘缓存；持久化历史放在**自己的家目录 `~/.zmarketplace/history.json`**（写时先写 tmp 再 rename 原子替换，损坏文件备份后重建）。它没有用 `~/.pi/agent` 下的专属目录。
   - 来源：tarball `zmarketplace@0.7.8` src/core/cache.ts、src/core/history.ts（https://github.com/zico20047/zmarketplace ）
4. `~/.pi/agent/` 下已占用的子目录（勿冲突）：`extensions/`（自动发现扩展，**该目录下每个 .ts/.js 都会被加载**，不能随便放数据文件）、`npm/`、`git/`、`tmp/extensions/`、`sessions/`、`themes/`、`prompts/`、`tools/`、`bin/`、`auth.json`、`trust.json`、`settings.json`、`models.json`、`pi-debug.log`。
   - 来源：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/config.ts

---

## 7. `pi install` vs `pi update` 的确切行为差异（pinned 跳过）

以下全部来自 main 分支源码（core/package-manager.ts、package-manager-cli.ts）：

### 7.1 `pi install <source>`

- CLI 调 `installAndPersist(source, {local})` = 先 `install()` 再 `addSourceToSettings()`。
- `install()`（npm）：在 `getNpmInstallRoot(scope)`（用户 `~/.pi/agent/npm`，项目 `.pi/npm`）执行 `npm install <spec> --prefix <root> --legacy-peer-deps`（bun: `--cwd` + `--omit=peer`；pnpm: `--prefix` + 三个 config flag）。首次会生成占位 `package.json`（`pi-extensions`/private）与 `.gitignore`。**不触碰 settings**。
- `addSourceToSettings()`：向对应 scope 的 settings `packages` **新增**条目；若按包身份（`npm:<name>`）已存在条目则**原位替换**为新的 source 字符串（保留 object 形式的其它过滤字段，仅更新 `source`）。**这就是"把包固定到某版本"的正规方式：`pi install npm:pkg@1.2.3` 会把 settings 条目改写为 `npm:pkg@1.2.3`。**
- 默认写用户 settings；`-l` 写项目 settings。项目 scope 安装要求项目 trust。
- 来源：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/package-manager.ts （install/installAndPersist/addSourceToSettings/getNpmInstallArgs，addSourceToSettings 约 821-854 行）；https://pi.dev/docs/latest/packages （Install and Manage）

### 7.2 `pi update [source]` / `--extensions` / `--all`

- `pi update`（无参数）默认只更新 pi 自身，且打印提示 "Extensions are skipped. Run pi update --extensions to update extensions."；`--extensions` 只更新包；`--all` = pi + 包；`--models` 只刷新模型目录；`--self` 只更新 pi。
- `pi update <source>`（如 `pi update npm:foo` 或 `pi update --extension npm:foo`）：按**包身份**（`npm:<name>`，忽略用户输入的版本）匹配 settings 中条目，然后对匹配条目执行更新流程。
- 更新流程（`updateConfiguredSources`，约 1110-1135 行）中的 **pinned 跳过逻辑（源码原文位置）**：
  ```typescript
  if (parsed.type === "npm") {
    if (!parsed.pinned) { npmCandidates.push({ ...entry, parsed }); }
  } else if (parsed.type === "git") { gitCandidates.push(...); }
  ```
  注释：'Pinned npm versions are fixed. Pinned git refs are configured checkout targets...'。**`parsed.pinned` 仅在 npm version 是精确 semver（`semver.valid` 非空）时为 true**；`^1.0.0` 之类 range 不算 pinned。同理 `checkForAvailableUpdates()` 对 `parsed.pinned || local` 直接返回 undefined。
- 对未 pinned 的 npm 条目：先 `shouldUpdateNpmSource`（比较 installed package.json version 与 `npm view` 得到的目标版本——有 range 时取 `maxSatisfying`，无 version 时取 latest），需要更新才批量 `npm install <name>@latest --prefix ...`（settings 里若无版本则安装目标始终是 `@latest`，且**settings 条目字符串保持不变**，不写回具体版本）。
- 对 git 条目：**不做"更新到新 ref"**，只把已有 clone **reconcile 到 settings 里配置的 ref**（reset + clean + 若有 package.json 则 `npm install --omit=dev`）；换 ref 要用 `pi install git:...@new-ref`。
- local 路径条目：完全不参与更新。
- **一个重要推论（已从源码确认）**：`pi update npm:pkg@1.2.3` 不能用于"把包更到 1.2.3"——它按身份匹配后用的是 **settings 里的旧条目字符串**；若该条目本身是 pinned 的（如 `npm:pkg@1.0.0`）会被直接跳过。升/降级到指定版本的唯一正规入口是 `pi install npm:pkg@1.2.3`（改写 settings 条目 + 安装精确版本）。
- 来源：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/package-manager.ts （update/updateConfiguredSources/shouldUpdateNpmSource/updateNpmBatch/isExactNpmVersion）；https://pi.dev/docs/latest/packages （npm/git 两节明确："Versioned specs are pinned and skipped by package updates"、git refs 不前移仅 reconcile）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/package-manager-cli.ts （update 目标解析与提示）

### 7.3 `pi remove`

`removeAndPersist`：`npm uninstall <name> --prefix <root> [--legacy-peer-deps]`（bun/pnpm 变体）+ 从 settings 删除条目；找不到匹配条目时报错退出码 1。local 源只删 settings 条目不动磁盘。

---

## 8. TypeScript 加载机制

1. **加载器**：jiti（`jiti@2.7.0`，`createJiti` from `jiti/static`），`jiti.import(extensionPath, { default: true })`；**无需预编译、无 tsconfig 要求**（TS/JS 均可；`moduleCache: false`，每次加载重新转译，配合 `/reload` 热重载——仅自动发现位置的扩展支持 `/reload`）。
2. **宿主包的虚拟模块**：`@earendil-works/pi-coding-agent`、`@earendil-works/pi-ai`（→ compat 入口）、`@earendil-works/pi-agent-core`、`@earendil-works/pi-tui`、`typebox`（含 `@sinclair/typebox` 别名）以及旧 scope `@mariozechner/*` 别名都通过 jiti `virtualModules`（编译二进制）或 alias（Node 构建）映射到 **pi 自带的运行实例**——扩展 import 这些包时不会也不需要自己安装。**这些包应声明为 peerDependencies `"*"` 且不打包**（官方 packages 文档 Dependencies 一节）。
3. **自己的 npm 依赖**：可以。在扩展包里放 `package.json` 声明 `dependencies`，`pi install` 安装该包时会对包目录执行 `npm install`（生产安装 `--omit=dev`；配置了 `npmCommand` 的 git 包用普通 `install`）。运行时 jiti 按文件路径向上解析 `node_modules/`，包自己的依赖装在自己的 `node_modules`（即 `~/.pi/agent/npm/node_modules/<pkg>/node_modules/`）中被正常解析。Node 内建（`node:fs`、`node:child_process`、`node:os` 等）直接可用。
   - 注意：`devDependencies` 在运行时**不可用**（安装用 `--omit=dev`）；需要 import 的都必须在 `dependencies`。
   - 其他 pi 包（非宿主核心）必须 bundle 进 tarball：放 `dependencies` + `bundledDependencies`，经 `node_modules/` 路径引用其资源（pi 按独立 module root 加载各包，互不冲突）。
4. **Node 版本**：`@earendil-works/pi-coding-agent@0.84.3` 的 `engines: { node: ">=22.19.0" }`。jiti 转译时使用 esbuild，扩展 TS 语法受其支持范围约束（常规 TS/JSX 均可；未见额外 tsconfig 要求）。
5. 自动发现位置：`~/.pi/agent/extensions/*.ts`、`~/.pi/agent/extensions/*/index.ts`、项目 `.pi/extensions/` 同构（项目级需 trust 后才加载）；`-e/--extension` 可临时加载文件或 `npm:`/`git:` source（装到 `~/.pi/agent/tmp/extensions` 临时目录，仅当次有效）。包形式的扩展入口由 `package.json` 的 `pi.extensions` 数组（glob 支持）或约定目录 `extensions/` 决定。

- 来源：https://pi.dev/docs/latest/extensions （Available Imports / Extension Locations / Writing an Extension）；https://pi.dev/docs/latest/packages （Dependencies / Package Structure）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/extensions/loader.ts （VIRTUAL_MODULES、createJiti 选项、moduleCache:false）；https://github.com/earendil-works/pi/blob/main/packages/coding-agent/package.json （jiti 版本、engines）

---

## 9. 对本项目（safe-update 扩展）直接可复用的事实速查

| 需求 | 已验证的事实 |
| --- | --- |
| 注册 `/safe-update` | `pi.registerCommand("safe-update", { description, handler: async (args, ctx) => {} })`；args 是整段字符串 |
| 让用户挑包 | `ctx.ui.select` 只有单选（`string[]`）；多选/表格需 `ctx.ui.custom()` 自绘组件（仅 `ctx.mode === "tui"`） |
| 列出已装包/版本 | 读 `~/.pi/agent/npm/node_modules/<name>/package.json` 的 `version`；或 `import { DefaultPackageManager } from "@earendil-works/pi-coding-agent"` 后 `listConfiguredPackages()` |
| 查谁有新版本 | `DefaultPackageManager.checkForAvailableUpdates()`（自动排除 pinned/local） |
| 执行更新 | `pi.exec("pi", ["install", "npm:<pkg>@<ver>"], { cwd: ctx.cwd })`（先例：pi-secure-extension）；注意 `pi update npm:pkg@ver` 对 pinned 条目无效，升指定版本用 `install` |
| 读写 settings | `SettingsManager.create(cwd, getAgentDir())` + `setPackages/setProjectPackages` + `flush()`（公开导出，带文件锁）；勿裸 fs 写 |
| 拿待审计的新版本源码 | 先例：`npm pack <spec> --pack-destination <tmp> --ignore-scripts` + `tar xzf`（pi-secure-extension source-resolver.ts，--ignore-scripts 防安装脚本执行） |
| 存配置/缓存 | 无官方 API；先例：全局 `~/.pi/agent/extensions/<name>-*.md`（避开 .ts/.js 扩展自动加载）或项目 `join(ctx.cwd, CONFIG_DIR_NAME, "<name>.json")`（读前查 `ctx.isProjectTrusted()`）；zmarketplace 用 `~/.zmarketplace/` 自有目录 |
| 中止/超时 | `pi.exec` 支持 `{signal, timeout}`；dialog 支持 `{signal, timeout}` |
| 长任务提示 | `ctx.ui.setStatus(key, msg)` / `setWidget` / `setWorkingMessage`；完成后 `ctx.ui.notify(msg, "info"\|"warning"\|"error")` |

---

## 10. 未能确认 / 存疑的事项

1. **settings 文档的裸 npm 名示例**（`"pi-skills"`）：文档与仓库 docs 均如此写，但 main 分支 `parseSource`+`isLocalPath` 会将无前缀字符串归为本地路径；未找到任何裸名 → npm 的 fallback 代码。判定为文档示例瑕疵，实现一律用 `npm:` 前缀即可规避。
2. **`~/.pi/agent/npm` 并发写入的官方态度**：源码层面无进程锁，未见文档/issue 明确讨论两个 pi 进程并发 install 的竞态（npm 自身行为决定后果）。单扩展内串行 spawn 是安全的；避免与用户同时手动跑 `pi update` 属于产品决策而非已证事实。
3. **jiti 对 TS 语法的精确支持边界**（esbuild 版本、decorator/特定 target 支持）：未逐一验证，常规 TS 语法按文档"TypeScript works without compilation"即可。
4. pi.dev 文档 `ctx.ui` 章节未罗列 `setHiddenThinkingLabel`、`onTerminalInput` 等全部方法（类型定义里有）；如需使用以 types.ts 为准。
