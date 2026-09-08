# Quake (360) Query Patterns — API v3

Endpoint: `POST https://quake.360.net/api/v3/search/quake_service`
Headers: `X-QuakeToken` + browser UA (curl default UA gets q5000).
DSL: Lucene style, operators `AND` / `OR` / `NOT`.

## 内容检索（查找同类首选）

```text
response:"__zr_probe__"
response:"api_tamper_count"
response:"app.2370c4bd.js"
```

`response` 是端口原始响应（含 HTTP 头+正文），是"以内容找站"的核心。实测
`response:"zr_probe"` 直接命中 163 个同类资产。加引号避免分词。

## 精确资产

```text
domain:"example.com"          # 含子域
domain:*.example.com          # 通配
ip:"1.2.3.4"
ip:"1.2.3.4/24"
ip:"154.40.43.28" AND service:"http"
hostname:"xxx.example.com"
cert:"example.com"
title:"登录"
app:"nginx"
favicon:"<md5>"               # 网页 favicon md5
html_hash:"<md5>"             # 基础会员 API 检索深度字段受限，结果需实测
```

## 地理过滤

```text
country_cn:"中国"
NOT country_cn:"中国"          # 境外
province_cn:"香港"
```

## 频率与配额

- 基础会员约 **10 秒 1 次**（q3005 = 调用频繁，等 13s 重试）。
- 每次查询扣积分（`/api/v3/user/info` 可查余额）。
- `quake_search.py` 已内置限频与 q3005 自动重试，不要绕过它并发调用。

## 基础会员字段权限

可用：`ip / port / domain / hostname / org / asn / time /
location(country_cn,province_cn,city_cn,isp) / service.name / service.http.title`

无权限（显示 `暂无权限`）：`service.http` 里的 `html_hash / favicon / body /
status_code / response_headers`。
