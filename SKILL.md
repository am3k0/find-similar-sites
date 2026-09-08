---
name: find-similar-sites
description: Find sites that share the same CMS, template, cloaking kit or infrastructure as a seed URL, with a fast first-result mode. Use when the user provides a URL/domain and wants similar or related sites. Results are printed to the conversation — never written to files.
---

# Find Similar Sites（同类站点查找）

给一个 URL，找到**可用的同类站点**并直接在对话里给出结果。

## 硬性约束（AI 调用本 skill 时必须遵守）

1. **禁止创建任何文件**。不要写报告 / CSV / JSON / 日志 / 临时脚本，不要在工作区或 skill 目录里留下任何东西。所有脚本都只把结果打印到 stdout；中间数据由脚本内部用系统临时目录处理并自动清理。
2. **禁止现场编写新脚本**。一切功能都在 `scripts/` 里；如果某个能力缺失，正确做法是升级本 skill 的脚本，而不是在运行时另写一个。
3. **快速优先**。默认只用 `find_similar.py` 一条命令；它找到第一个合格站点就停。只有用户明确要求深度分析时才用分步脚本。
4. **结果只需要结论**。给出一行结论 + 证据要点（IP、归属地、证据类型、是否国内标记），不要生成报告文件。

## 默认用法（快速模式）

```powershell
python scripts/find_similar.py 77x22.cc                 # 找到即停
python scripts/find_similar.py http://x.example/ -v     # 显示过程
python scripts/find_similar.py x.example --all          # 列出全部合格候选
python scripts/find_similar.py x.example --budget 120   # 限时 120 秒
```

输出示例：

```
✅ 同类站点: http://candidate.example
   IP: 103.1.2.3 (美国/加利福尼亚) | 采集: rule
   证据: R3 含种子特有标记 '__zr_probe__'; CSS 相似 88%; DOM 相似 95%
   合规: IP/CNAME 与种子及跳转链无交集 | 级别: same_content | 分数 9
```

## 网络规则（反诈拦截绕过）

本机网络会把被拦截域名 302 到反诈页或把 DNS 污染成 0.0.0.0。所有采集脚本内置回退链：

```
直连 → 拦截识别 → 规则代理 http://127.0.0.1:7897 → 全局代理 http://127.0.0.1:7898 → 浏览器渲染
```

- 代理只在直连被拦截/失败时使用（`net_utils.fetch` 自动处理，无需手工指定）。
- 浏览器渲染（`browser_fetch.py`）用 Chrome/Edge 无头模式，`--proxy auto` 同样自动选择。
- 拦截特征：302 到纯 IP、`response.html`、标题含 反诈/警告/访问受限、DNS 解析 0.0.0.0/127.0.0.1。

## 同类站判定规则（用户定义，验证器强制执行）

| 规则 | 内容 |
|---|---|
| R1 | 候选与种子（**含跳转后的站点**）不能同 IP、不能同 CNAME |
| R2 | 种子是国内 IP 时，候选优先境外（含港澳台）；只有国内的候选必须标记 `[国内IP]` |
| R3 | 必须基于**真实页面内容**验证（body 哈希 / CSS≥70% / DOM≥80% / favicon / 特有标记），拦截页不算内容 |

## 凭据与配置

```powershell
python scripts/init.py --quake-token XXX --hunter-key XXX
python scripts/init.py --flint-user U --flint-pass P
python scripts/init.py --proxy-rule http://127.0.0.1:7897 --proxy-global http://127.0.0.1:7898
python scripts/init.py --validate        # 网络+代理+三个凭据全量体检
python scripts/init.py --status          # 查看当前配置（脱敏）
```

配置加密存于 `~/.codex/find-similar-sites/config.enc`（AES-256-GCM）。

## 数据源能力

| 源 | 用途 | 注意 |
|---|---|---|
| Quake 360 v3 | `response:"标记"` **内容检索**（最强）、domain/ip/title/cert | 基础会员约 10 秒 1 次（脚本自动限频重试）；必须带浏览器 UA；html_hash/favicon 深度字段无权限 |
| Hunter v3.0.1 | `web.body/web.title/ip/domain/cert`，支持 `status_code`、`port_filter`、`is_web=3` 参数 | page_size 只能 1/10/20/50/100；积分制 |
| Flint 平台 | DNS 历史（CNAME 链、历史 IP）、同 CDN/CNAME 站点 | 可选，配了自动启用 |
| CT 日志 | 证书 SAN 关联 | 快速模式不用 |
| 无头浏览器 | JS 渲染页真实内容、跳转目标 | 只在 HTTP 采集失败/可疑时用（较慢） |

## 分步脚本（仅深度分析时使用）

| 脚本 | 用途 |
|---|---|
| `find_similar.py <url>` | **快速模式主入口**（默认就用这个） |
| `quake_search.py '<dsl>'` | Quake 检索（限频自动处理） |
| `hunter_search.py '<dsl>'` | Hunter 检索（v3.0.1 参数） |
| `browser_fetch.py <url>` | 无头浏览器渲染单页 |
| `fingerprint_site.py <url>` | 传统三级指纹采集 |
| `dns_history.py <host>` | Flint DNS 历史 |
| `flint_cms_pivot.py <host>` | 同 IP/CNAME 站点 |
| `ct_pivot.py <domain>` | 证书透明度 |
| `validate_candidate.py` | 规则验证器（R1/R2/R3） |
| `origin_probe.py` / `url_collection.py` / `app_discovery.py` | 直连源站 / URL 库 / APP 链 |
| `init.py` | 配置与体检 |

## 安全

只读操作：GET 页面、查询 API。不登录、不提交表单、不绕过验证码。
