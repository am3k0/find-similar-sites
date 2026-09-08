# find-similar-sites

给 AI 工具用的同类站点发现 skill：输入 URL，一条命令给出**可用的同类站点**（对话直出，不产文件）。

## 快速模式（默认）

```powershell
python scripts/find_similar.py 77x22.cc
```

33 秒级出结果：种子采集（反诈自动绕过）→ Quake/Hunter/Flint 并行检索 →
R1(IP/CNAME 独立，含跳转链)过滤 → 真实页面内容验证 → 找到即停。

## 数据源

| 源 | 说明 |
|---|---|
| Quake 360 v3 | `response:"标记"` 内容检索（核心）；基础会员 10s/次，脚本自动限频 |
| Hunter v3.0.1 | `web.body` 内容检索；新增 `status_code`/`port_filter`/`is_web=3` 参数 |
| Flint | DNS 历史（CNAME/历史 IP）、同 CDN 站点（可选） |
| 无头浏览器 | Chrome/Edge 渲染 JS 页面，HTTP 采集失败/可疑时自动启用 |

## 反诈绕过（本机网络必备）

直连 → 拦截识别 → 规则代理 `http://127.0.0.1:7897` → 全局代理 `http://127.0.0.1:7898` → 浏览器。
拦截特征：302 到纯 IP、`response.html`、标题 反诈/警告/访问受限、DNS 0.0.0.0/127.0.0.1。

## 判定规则（用户定义）

1. 候选与种子（含跳转后站点）不能同 IP / 同 CNAME
2. 种子国内 IP → 候选优先境外（含港澳台）；只有国内的标记 `[国内IP]`
3. 必须基于真实页面内容验证（body 哈希/CSS/DOM/favicon/特有标记）

## 配置

```powershell
python scripts/init.py --quake-token XXX --hunter-key XXX
python scripts/init.py --flint-user U --flint-pass P
python scripts/init.py --validate
```

## 硬约束

调用本 skill 的 AI：**不要创建任何文件**（报告/CSV/JSON/临时脚本都不要），
一切用 `scripts/` 专用脚本完成，结果直接回复在对话里。
