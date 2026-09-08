# Hunter Query Patterns — openApi v3.0.1

Endpoint: `GET https://hunter.qianxin.com/openApi/search`
Params: `api-key, search(urlsafe-base64 DSL), page, page_size, is_web,
start_time, end_time, status_code, port_filter`

## v3.0.1 变更（实测确认）

- **`status_code` 参数**：服务端过滤状态码（实测 baidu.com 查询 36415 → 30612）。
- **`port_filter`**、**`is_web=3`（全部资产）** 合法。
- `page_size` 合法值仅 **1 / 10 / 20 / 50 / 100**（其他值报 400 页大小不合法，
  `hunter_search.py` 会自动吸附到最近合法值）。
- 响应字段扩展到 28 个：`as_org, asset_tag, banner, base_protocol, cert_sha256,
  city, company, component, country, domain, header, header_server,
  icp_exception, ip, ip_tag, is_risk_protocol, is_web, isp, number, os, port,
  protocol, province, ssl_certificate, status_code, updated_at, url, web_title`

## 内容检索（查找同类首选）

```text
web.body="app.2370c4bd.js"&&web.body="chunk-vendors.19e904fa.js"
```

两个哈希资产名同时命中 = 同一前端构建。

```text
web.body="/assets/news/comm.js"&&web.body="dynamic-card-container"
```

一条稀有脚本路径 + 一个结构性标记。

## 资产/维度

```text
domain="app.example.com"        domain.suffix="example.com"
ip="1.2.3.4"                    ip.port="8080"
web.title="xxx"                 cert="example.com"
icp.name="xxx"                  icp.number="京ICP备xxxx号"
header.server="nginx"           protocol="http"
country="美国"                  city="Hangzhou"
```

## 误报控制

不要单独依赖：`web.title="app"`、`header.server="nginx"`、通用框架名
（Vue/React/Tailwind/Vite）、仅有 favicon 哈希而无正文/路由证据。

## 配额纪律

1. 先 `--page-size 1`（或 10）看 total。
2. 记录 `rest_quota`。
3. total 可控再放大 page_size。
4. `hunter_search.py` 自带 429 重试，不要并发轰炸。
