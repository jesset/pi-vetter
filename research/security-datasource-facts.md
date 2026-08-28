# pi 扩展安全扫描:各安全数据源接入事实核查

- 核查日期: 2026-08-28(所有 curl 实测均于当日执行)
- 用途: 为多路安全评估器(OSV / OpenSSF / npm provenance / VirusTotal / Socket)确认接入事实
- 方法: 官方文档 + 仓库源文件 + `curl` 对线上 API 实测;未能确认的事项均明确标注
- 本文只陈述事实,不做设计决策

---

## 1. OSV.dev API 与 OpenSSF Malicious Packages 的关系

### 结论
**是的。ossf/malicious-packages 的通告以 OSV 格式存储,且被 osv.dev 官方收录为数据源(MAL- 前缀 ID)。用 OSV `/v1/querybatch` 查 npm 包@版本可以直接命中恶意包通告。**

### 证据

1. 仓库自述(官方): "This repository is a collection of reports of malicious packages identified in Open Source package repositories, consumable via the Open Source Vulnerability (OSV) format.",通告文件位于仓库 `osv/` 目录(含 `osv/withdrawn/`)。
   - 来源: <https://github.com/ossf/malicious-packages>
2. osv.dev 官方数据源清单 `source.yaml` 中明确登记两个来源(实测抓取 master 分支原文,含行号):
   - `malicious-packages`(L395-408): `repo_url: 'https://github.com/ossf/malicious-packages.git'`、`directory_path: 'osv'`、`db_prefix: ['MAL-']`、`accepted_ecosystems: ['*']`(注释: "All ecosystems (we trust malicious packages)")
   - `ghsa`(L314-328): `db_prefix: ['GHSA-']`、`directory_path: 'advisories/github-reviewed'`、`accepted_ecosystems: ['*']`
   - 来源: <https://github.com/google/osv.dev/blob/master/source.yaml>
3. 实测(2026-08-28,均成功):
   - `GET https://api.osv.dev/v1/vulns/MAL-2022-2` → 返回完整 OSV 记录:"Malicious code in --hiljson (npm)",aliases 含 `GHSA-qqfx-rpxc-ghp4`,`database_specific.malicious-packages-origins` 标注来源(该条来自 `ghsa-malware` 源)。
   - `POST /v1/querybatch`(body 见下方附录)返回:
     ```json
     {"results":[
       {"vulns":[{"id":"MAL-2022-2"}]},                              // npm --hiljson@0(受影响区间 introduced:"0")
       {"vulns":[{"id":"GHSA-xvch-5gv4-984h"}]},                     // npm minimist@1.2.5
       {"vulns":[{"id":"GHSA-qw6h-vgh9-j6wx"},
                 {"id":"GHSA-rv95-896h-c2vc"}]}                      // npm express@4.18.2
     ]}
     ```
     即:恶意包通告(MAL-)与漏洞通告(GHSA-)在同一次 querybatch 中命中。querybatch 只返回 vuln ID 列表,详情需再查 `/v1/vulns/{id}`。
   - `POST /v1/query` 查 `node-ipc@10.1.1` → 命中 `GHSA-97m3-w2cp-4xx6`(Embedded Malicious Code,即 GitHub Advisory Database 中 "Malware" 类型通告也收录在 OSV)。
4. 数据新鲜度 SLO(官方 FAQ): "Data sources no more than 15 minutes stale, 99.5% of the time."
5. API 限流(官方 FAQ 原文): "Currently there is not a limit on the API."(另有 HTTP/1.1 响应 32MiB 大小限制,HTTP/2 无限制)。
   - 来源: <https://google.github.io/osv.dev/faq/>,API 参考: <https://google.github.io/osv.dev/api/>

### 未确认/注意
- MAL- 记录的 affected 通常为 `introduced: "0"` 区间(整包判恶意),部分记录也列出显式 `versions`;querybatch 对任意版本均可命中,评估器不应假设"仅特定版本恶意"。
- osv.dev FAQ 未逐一列出数据库来源,完整清单即上述 `source.yaml`(MAL-/GHSA- 均在)。

---

## 2. OpenSSF Package Analysis 的公开数据访问

### 结论
**分析结果(文件访问/网络连接/命令执行等行为)通过 BigQuery public dataset 公开;项目未提供 HTTP API。数据集为项目 `ossf-malware-analysis`、dataset `packages`、表 `analysis`,另提供表函数 `packages.analysis_for_phase(phase)`。动态分析对象主要是各 ecosystem 的"新增包"(经 package-feeds 监控),不是 npm 全量历史包的覆盖。**

### 证据

1. README "Public Data" 一节(官方原文): "This data is available in the public BigQuery dataset",链接的控制台 URL 参数为 `d=packages&p=ossf-malware-analysis&t=analysis`。
   - 来源: <https://github.com/ossf/package-analysis>
2. 官方查询示例(实测抓取仓库 `docs/queries.md`)使用:
   ```sql
   `ossf-malware-analysis.packages`.analysis_for_phase(PHASE)   -- PHASE = "import" / "install"
   ```
   示例中 `LOOKBACK_DAYS INT64 DEFAULT 2`,说明数据天级新鲜(查询近 2 天)。注意: BigQuery 查询可能对使用者自己的 GCP 项目产生费用(文档原注)。
   - 来源: <https://github.com/ossf/package-analysis/blob/main/docs/queries.md>
3. 结果 JSON schema(实测抓取 `docs/data_schema.md`):字段含 `Files[]`(Path/Read/Write/Delete)、`Sockets[]`(Address/Port/Hostnames)、`Commands[]`(Command/Environment)、`DNS[]`;`Ecosystem` 枚举 "Currently supported values are **pypi, npm, packagist, rubygems, crates.io**"。
   - 来源: <https://github.com/ossf/package-analysis/blob/main/docs/data_schema.md>
4. 覆盖范围与新鲜度(README 原文): "Package repositories are monitored for new packages." / "Each new package is scheduled to be analyzed by a pool of workers."——即主要分析**新增包**,配合 package-feeds(feeds 类型含 pypi/npm/rubygems/crates 等)。
   - 来源: <https://github.com/ossf/package-analysis>,<https://github.com/ossf/package-feeds>
5. 与 ossf/malicious-packages 的关系:malicious-packages README 原文 "This project is closely related to the OpenSSF Package Analysis project.";MAL- 记录的 `database_specific.malicious-packages-origins` 记录来源(如 `ghsa-malware`);未发现 "每个 MAL 记录都对应一条 BigQuery 动态分析" 的官方对应关系说明。

### 未确认
- 无 HTTP API(README 未提及,确认"无")。
- 早年社区资料提到的 GCS 公开 bucket(如 `gs://ossf-malware-analysis-reports`):当前 README/docs 未将其列为公开访问方式,仅在部署配置中出现结果 bucket 变量(`OSSF_MALWARE_ANALYSIS_RESULTS`)。**公开 bucket 访问方式未在官方文档确认,接入应以 BigQuery 为准。**
- "是否只覆盖部分 npm 包":官方口径是新增包流式分析;BigQuery 表中历史存量的确切覆盖比例未给出官方数字。

---

## 3. npm registry 元数据中的 provenance / attestations

### 结论
**`GET https://registry.npmjs.org/<pkg>`(完整 packument)中,若版本带 provenance,则该版本的 `dist.attestations` 含 `{url, provenance.predicateType}`;该 `url` 可直接 GET 到 sigstore bundle(DSSE + 透明日志 + Fulcio 证书),全程无需安装包。npm CLI 侧 `npm audit signatures` 只作用于已安装依赖树(自 v9.6.0 起同时验证 attestations,v11.12.0 起 `--include-attestations` 可输出 bundle);对未安装包的独立验证可用 `@sigstore/verify` 库或 `@sigstore/cli`(`sigstore verify BUNDLE`)。**

### 证据

1. `dist.attestations` 字段形状(实测,`@sigstore/verify@4.1.2`,完整 packument 默认 Accept):
   ```json
   "dist": {
     "integrity": "sha512-...",
     "shasum": "...",
     "tarball": "https://registry.npmjs.org/@sigstore/verify/-/verify-4.1.2.tgz",
     "attestations": {
       "url": "https://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2fverify@4.1.2",
       "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
     }
   }
   ```
   同机实测 typescript/express 最新版 `dist` 中**无** attestations 字段(provenance 非全量覆盖)。
2. GET 该 attestations url(实测解码):
   - 顶层 `{"attestations":[{bundle},...]}`,共 2 个 bundle;
   - bundle `mediaType: application/vnd.dev.sigstore.bundle+json;version=0.2`;
   - DSSE envelope `payloadType: application/vnd.in-toto+json`,payload 为 in-toto Statement v0.1,`subject` 形如 `pkg:npm/%40sigstore/verify@4.1.2` + `digest.sha512`;
   - bundle[0] predicateType `https://github.com/npm/attestation/tree/main/specs/publish/v0.1`(publish attestation,keyed 签名 + `tlogEntries`);bundle[1] predicateType `https://slsa.dev/provenance/v1`(provenance,`verificationMaterial.certificate.rawBytes` 为 Fulcio 证书 + `tlogEntries`)。
3. `npm audit signatures` 的作用范围(官方文档 "Verifying ECDSA registry signatures"):Prerequisites 为 "Install npm CLI version v8.15.0 or later" + "Install dependencies using `npm install` or `npm ci`";验证输出针对已安装包("audited 1640 packages ... have verified registry signatures")。即**只对本地已安装树有效**。
   - 来源: <https://docs.npmjs.com/verifying-registry-signatures>
4. `npm audit signatures` 会验证 attestations:PR #6153 "feat: audit signatures verifies attestations"(merged 2023-02-14,落地 npm **v9.6.0**,changelog 原文 "audit signatures verifies attestations (@feelepxyz)";PR 描述 "Update `audit signatures` to also verify Sigstore attestations",引用 RFC npm/rfcs#626)。
   - 来源: <https://github.com/npm/cli/pull/6153>、<https://github.com/npm/cli/blob/v9.6.0/CHANGELOG.md>
5. npm **v11.12.0**(2026-03-18)新增 `npm audit signatures --include-attestations` 输出完整 sigstore attestation bundles(changelog "audit: add --include-attestations flag to output sigstore bundles")。
   - 来源: <https://github.com/npm/cli/pull/9049>、<https://github.com/npm/cli/blob/latest/CHANGELOG.md>
6. 独立库/CLI(不经 npm 安装流程):
   - `@sigstore/verify`:官方描述 "A library for verifying Sigstore signatures"(README 较简略;Node 要求 ^22.22.2 || ^24.15.0 || >=26)。
     - 来源: <https://github.com/sigstore/sigstore-js/tree/main/packages/verify>
   - `@sigstore/cli`:`sigstore verify BUNDLE`(验证 bundle 文件)、`sigstore attest FILE`(签名)。
     - 来源: <https://github.com/sigstore/sigstore-js/tree/main/packages/cli>
   - 参考: 本机 npm 10.9.8 / node v22.23.2;npm CLI v12.0.2 自身仅依赖 `@sigstore/tuf`。

### 未确认
- `dist.attestations` 字段**未出现在** npm registry 官方文档 `docs/responses/package-metadata.md` 中(该文档只说明 full/abbreviated 两种 packument);字段形状以上述实测为准。
- abbreviated packument(`Accept: application/vnd.npm.install-v1+json`,安装用 corgi 文档)按官方说明 "only the fields required to support installation",**不保证**含 attestations/maintainers/time;读取信誉与 provenance 字段需用完整 packument(默认 Accept 即可)。
  - 来源: <https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md>
- "jsr/sigstore"(JSR 上的 sigstore 包)未查证。

---

## 4. npm 下载量 / 元数据 API

### 结论
**下载量 API 无官方公布的 per-minute 限流数值,官方文档只给出批量/时间范围限制;registry packument 提供多个可用信誉信号字段(maintainers、time、deprecated、versions 数量等)。**

### 证据

1. 端点与限制(官方 download-counts.md 原文):
   - `GET https://api.npmjs.org/downloads/point/{period}[/{package}]`、`/downloads/range/{period}[/{package}]`;bulk 用逗号分隔包名。
   - "Bulk queries are limited to at most **128** packages at a time and at most **365 days** of data.";其他查询至多 18 个月;数据起点 2015-01-10;"Scoped packages are not yet supported in bulk queries."。
   - 按版本: `GET https://api.npmjs.org/versions/{package}/last-week`(仅保留最近 7 天)。
   - 更新频率: "Once per day, soon after UTC midnight"。
   - 来源: <https://github.com/npm/registry/blob/main/docs/download-counts.md>
2. 限流政策: **官方文档未给出 per-minute/per-day 数字限流**(只有限制批量与历史范围);实测响应头(Cloudflare,`cache-control: public, max-age=300`,无 `x-ratelimit-*` 头)。
3. 实测(2026-08-28): `GET https://api.npmjs.org/downloads/point/last-week/express` → `{"downloads":132239265,"start":"2026-08-20","end":"2026-08-26"}`;`/range/2026-08-01:2026-08-27/express` 返回按天数组。
4. 信誉信号字段(完整 packument 实测):
   - `maintainers`: `[{name, email}, ...]`(express 5 人、request 4 人);
   - `time`: `created` / `modified` / 每个版本的发布时间戳(request created 2011-01-22,latest 2.88.2 发布于 2020-02-11);
   - `deprecated`: 版本级字符串(request@2.88.2: "request has been deprecated, see ...");
   - `versions` 对象条数(request 126、express 288);
   - 其他: `dist-tags`、`dist.integrity/shasum/tarball/unpackedSize/fileCount/signatures`。

### 未确认
- api.npmjs.org 的实际隐性限流阈值(如 Cloudflare 层)无官方数字,接入时需自测退避。

---

## 5. VirusTotal 上传 npm tarball 的合规性

### 结论
**政策层面:Public API 免费配额为 4 req/min、500 req/day,整体适用于 Public API(未按端点区分);但官方明确"上传 VT 中不存在的新文件不消耗配额"。上传的 Sample 会立即与 VT Partners 共享、且要求上传者愿意公开共享并拥有权利——公开 npm tarball 属公开可再分发工件,但逐包 license 兼容性需自行把关(ToS 原文见下)。**

### 证据(均为官方原文)

1. Public API 配额与用途定位(<https://docs.virustotal.com/reference/public-vs-premium-api>):
   > "The Public API is limited to **500 requests per day and a rate of 4 requests per minute**.
   > The Public API **must not** be used in commercial products or services.
   > The Public API **must not** be used in business workflows that do not contribute new files."
   - 该页未按端点区分限制(上传与查询同受此整体限额);"do not contribute new files" 表明 Public API 的预期用途是**贡献新文件**的工作流。
2. 上传端点(<https://docs.virustotal.com/reference/files-scan>):POST `/files`,multipart/form-data,认证头 `x-apikey`;"If the file to be uploaded is bigger than 32MB, please use the /files/upload_url endpoint instead"(upload_url 最高 650MB);返回 analysis ID,需再查 `/analyses/{id}`。
3. 上传是否占配额(<https://virustotal.readme.io/docs/quota-consumption.md>,官方文档):
   > "If you upload a new file to VirusTotal via /file/scan **it won't consume from your quota**. This means that you can freely upload **new files not found in VirusTotal** without consuming from your API quota."
   > (同页)"If a user uploads a new file that is not in VirusTotal, then no API quota will be consumed. Further calls to retrieve this file's data (`GET /files/{sha256}`) or its analyses (`GET /files/analyses/{id}`) won't consume quota either. Note that re-scanning the file (`POST /files/{sha256}/analyse`) will consume quota as any other API call."
   - 注意同页 v2 时代描述称后续 `/file/report` 查询会消耗配额;**两处表述并存,实际计量建议以实测为准**。
4. 样本共享政策(historic Terms of Service,<https://virustotal.readme.io/docs/historic-terms-of-service.md>):
   > "You understand that if you submitting any Sample, **the Sample is immediately shared for review by the Service's Partners**, and the resulting intelligence report is shared with you and, and with the Partners..."
   > "you are either the original owner of the Sample you submit or that you have the necessary rights and permissions to **irrevocably contribute** the Sample and share it... with the Community."
   > "YOU FURTHER AGREE THAT YOU WILL ONLY UPLOAD SAMPLES THAT YOU WISH TO **PUBLICLY SHARE**..."
   > "IF YOU DO NOT WANT TO PUBLICLY SHARE A SAMPLE... DO NOT SEND IT/CONTRIBUTE IT TO THE SERVICE AS THE SERVICE IS DESIGNED TO WORK THROUGH THE COLLECTIVE AGGREGATION AND SHARING OF THREAT-INTELLIGENCE..."
5. 商用/非商用区分(<https://virustotal.readme.io/docs/difference-public-private.md>):Public API = "Non-commercial, or academic use.";Private API 才允许 "Commercial or Government use"。

### 未确认
- VirusTotal 当前版 ToS 页(<https://docs.virustotal.com/docs/terms-of-service>)抓取内容为空壳(仅标题),以上共享条款引自官方留档的 historic ToS;当前版条款措辞可能有更新。
- "上传公开 npm tarball 是否完全合规"属于法律判断,本文只列政策原文:上传即公开共享 + 须拥有不可撤销的再分发权利;npm 公开包虽可公开下载,但其 license 可能含再分发附加义务(如保留声明),逐包把关属实现侧责任。

---

## 6. Socket.dev 免费层细节

### 结论
**API base `https://api.socket.dev`(v0);认证用 organization token,`Authorization: Bearer <api_key>` 或 Basic auth(username=key, password 空)。配额按"每端点消耗单位数 × 每 token 每小时上限"计量,超限返回 429 + `Retry-After`。免费层 500 API quota/hour。查询包 score/alerts 的现行端点是 PURL 批量端点(POST `/v0/orgs/{org_slug}/purl`),**每次调用消耗 100 单位**(即免费层约 5 次/小时);旧的 POST `/v0/purl` 已于 2026-01-05 弃用,更旧的 `GET /v0/npm/<pkg>` 形式已不存在(404)。**

### 证据(均为官方文档原文/实测)

1. 认证(<https://docs.socket.dev/reference/authentication.md>): "passing the API token as a Bearer token in the `Authorization` header, or as the username field of an HTTP Basic authentication header";示例 `--header 'authorization: Bearer your_api_key'`、`curl https://api.socket.dev/v0/quota -u "your_api_key:"`。
2. 配额机制(<https://docs.socket.dev/reference/quota.md>): "Each API endpoint has a **quota** and each API token has a **maximum quota** that can use **per hour**... the API will return a `429` error and the `Retry-After` header will contain the number of seconds until you can call that same endpoint successfully"。
3. 免费层数额(socket.dev 定价页原文,免费计划条目): "500 API quota per hour"、另有 "1,000 scans per month"。
   - 来源: <https://socket.dev/pricing>(HTML 内文案,实测抓取)
4. 端点计量示例(官方各端点页"consumes N units of your quota"标注):
   - `POST /v0/orgs/{org_slug}/purl`(Get Packages by PURL (Org Scoped),批量取包 metadata + alerts,请求体 `{"components":[{"purl":"pkg:npm/express@4.19.2"}]}`,batch 上限 1024):"**This endpoint consumes 100 units of your quota.**",需要 org token scope `packages:list`;支持 `alerts`/`actions`/`compact`/`poll` 等 query 参数。
     - 来源: <https://docs.socket.dev/reference/batchpackagefetchbyorg.md>
   - `POST /v0/purl`(Get Packages by PURL,无 org 前缀):"**This endpoint is deprecated.** Deprecated since 2026-01-05... This endpoint consumes 100 units of your quota."
     - 来源: <https://docs.socket.dev/reference/batchpackagefetch.md>
   - 对照:创建 full scan 消耗 1 单元(<https://docs.socket.dev/reference/createorgfullscan.md>);fetch fixes 消耗 10 单元(<https://docs.socket.dev/reference/fetch-fixes.md>)。
5. 旧式单包端点已下线(实测,无认证):`GET https://api.socket.dev/v0/npm/lodash`、`GET .../v0/npm/lodash/score` 均 404 "API route not found";`GET https://api.socket.dev/v0/quota` 返回 401(路由存在,需认证)。
6. score/alerts 数据口径:Socket 评分维度为 supply chain risk / quality / maintenance / vulnerabilities / license(<https://docs.socket.dev/docs/package-scores.md>);alerts 类型清单见 <https://docs.socket.dev/docs/alert-types.md>;另有 CLI `socket package`("Get score and other details on software packages",<https://docs.socket.dev/docs/socket-package.md>)。

### 未确认
- 免费层是否能创建 org token(即免费层可用哪些 API 端点)未在文档明示;上述 500 quota/hour 为定价页免费计划文案。
- PURL 端点响应体中 score 字段的具体结构未实测(需要 API key),文档描述为 "package metadata and alerts"。

---

## 7. GitHub Advisory Database 是否已被 OSV 覆盖

### 结论
**是。GHSA 通告(osv.dev 内 `db_prefix: GHSA-`)已收录进 osv.dev 并可通过 `/v1/query`、`/v1/querybatch` 查询(包含 npm 生态及 "Malware" 类型通告),因此做漏洞+恶意包查询时无需单独接 GitHub Security Advisories API。**

### 证据
1. `source.yaml` 的 `ghsa` 条目(L314-328):来源仓库 `github/advisory-database`,目录 `advisories/github-reviewed`,注释 "All ecosystems (We trust GHSA)"。
   - 来源: <https://github.com/google/osv.dev/blob/master/source.yaml>
2. 实测:querybatch 中 `minimist@1.2.5` → `GHSA-xvch-5gv4-984h`;`express@4.18.2` → `GHSA-qw6h-vgh9-j6wx` + `GHSA-rv95-896h-c2vc`;`/v1/query` 查 `node-ipc@10.1.1` → `GHSA-97m3-w2cp-4xx6`(Malware 类型)。
3. OSV FAQ 亦列出 GitHub Security Advisories 为 OSV schema 采用方。
   - 来源: <https://google.github.io/osv.dev/faq/>

### 未确认
- GitHub Advisory API 的附加能力(如按 CVE/CVSS 精细检索、advisory 修订历史)不在 OSV 查询能力内;若仅需"包@版本 → 通告列表"则 OSV 已覆盖。

---

## 附录:实测命令与输出摘要(2026-08-28)

```bash
# 1) OSV: 单条 MAL 记录
curl -s https://api.osv.dev/v1/vulns/MAL-2022-2
# → {"id":"MAL-2022-2","summary":"Malicious code in --hiljson (npm)",...,"aliases":["GHSA-qqfx-rpxc-ghp4"],...}

# 2) OSV: querybatch(恶意包 + GHSA 对照)
curl -s -X POST https://api.osv.dev/v1/querybatch -H 'Content-Type: application/json' -d '{
  "queries":[
    {"package":{"ecosystem":"npm","name":"--hiljson"},"version":"0"},
    {"package":{"ecosystem":"npm","name":"minimist"},"version":"1.2.5"},
    {"package":{"ecosystem":"npm","name":"express"},"version":"4.18.2"}]}'
# → MAL-2022-2 / GHSA-xvch-5gv4-984h / GHSA-qw6h-vgh9-j6wx + GHSA-rv95-896h-c2vc

# 3) npm attestations 元数据 + bundle
curl -s https://registry.npmjs.org/@sigstore/verify | jq '.versions["4.1.2"].dist.attestations'
curl -s 'https://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2fverify@4.1.2'
# → 2 个 sigstore bundle(publish/v0.1 + slsa.dev/provenance/v1),DSSE in-toto payload,subject=pkg:npm/...

# 4) 下载量
curl -s https://api.npmjs.org/downloads/point/last-week/express
# → {"downloads":132239265,"start":"2026-08-20","end":"2026-08-26","package":"express"}

# 5) Socket 旧端点已下线(未认证探测)
curl -s https://api.socket.dev/v0/npm/lodash        # → 404 API route not found
curl -s https://api.socket.dev/v0/quota             # → 401 Unauthorized(路由存在)
```
