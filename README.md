# alipay-sdk-go-all

支付宝开放平台 **V3 协议** Go 语言 SDK，对齐官方 [alipay-sdk-php-all](https://github.com/alipay/alipay-sdk-php-all) 仓库 v3 版本的核心能力与全量 API。

- 全量 API：由代码生成器从官方 `oasSchema.json` 生成 **2722 个 Model** 与 **746 个 API 方法**
- V3 协议：`ALIPAY-SHA256withRSA` 请求签名、响应验签、证书序列号（certSN/rootCertSN）、敏感信息 AES 加解密
- V2 兼容：`pageExecute` / `sdkExecute` 支持 App 支付、手机网站支付、电脑网站支付等页面类接口
- 异步通知：`RsaCheckV1`（公钥模式）/ `RsaCheckV1WithCert`（证书模式）/ `RsaCheckV2` 通用验签
- 跨平台：纯 Go 标准库 + [jcbaseGo](../jcbaseGo) 基础库，无 CGO，Win10 / macOS / Win11 均可直接编译

## 安装

```bash
go get github.com/jcbowen/alipay-sdk-go-all
```

本地开发依赖 jcbaseGo（见 go.mod 中的 `replace` 指令）。

## 快速开始

### 公钥模式

```go
package main

import (
	"fmt"

	"github.com/jcbowen/alipay-sdk-go-all"
	"github.com/jcbowen/alipay-sdk-go-all/api"
	"github.com/jcbowen/alipay-sdk-go-all/model"
)

func main() {
	configUtil, err := alipay.NewAlipayConfigUtil(&alipay.AlipayConfig{
		AppId:            "2021000100000000",
		PrivateKey:       "MIIEpAIBAAK...", // 商户私钥（裸 base64 串或 PEM 文本）
		AlipayPublicKey:  "MIIBIjANBgkq...", // 支付宝公钥
		EncryptKey:       "加密密钥（可选，敏感信息加密用）",
	})
	if err != nil {
		panic(err)
	}

	tradeApi, err := api.NewAlipayTradeApi(configUtil)
	if err != nil {
		panic(err)
	}

	result, apiErr := tradeApi.Pay(&model.AlipayTradePayModel{
		OutTradeNo:  alipay.Str("20240101123456"),
		TotalAmount: alipay.Str("0.01"),
		Subject:     alipay.Str("测试商品"),
		AuthCode:    alipay.Str("286666666666666666"),
	}, nil)
	if apiErr != nil {
		panic(apiErr)
	}
	fmt.Println(alipay.DerefStr(result.TradeNo))
}
```

### 证书模式

```go
configUtil, err := alipay.NewAlipayConfigUtil(&alipay.AlipayConfig{
	AppId:                    "2021000100000000",
	PrivateKey:               "MIIEpAIBAAK...",
	AppCertContent:           appCertPEM,      // 三类证书：Content 与 Path 二选一
	AlipayPublicCertContent:  alipayCertPEM,
	RootCertContent:          rootCertPEM,
})
// 也可用文件路径：AppCertPath / AlipayPublicCertPath / RootCertPath
```

## V3 接口调用

### 交易查询 / 退款

```go
// 查询
queryResult, apiErr := tradeApi.Query(&model.AlipayTradeQueryModel{
	OutTradeNo: alipay.Str("20240101123456"),
}, nil)

// 退款
refundResult, apiErr := tradeApi.Refund(&model.AlipayTradeRefundModel{
	OutTradeNo:   alipay.Str("20240101123456"),
	RefundAmount: alipay.Str("0.01"),
}, nil)
```

### 服务商代调用（appAuthToken）

```go
result, apiErr := tradeApi.Query(&model.AlipayTradeQueryModel{
	OutTradeNo: alipay.Str("123"),
}, &alipay.CustomizedParams{AppAuthToken: "服务商授权凭证"})
```

### 任意接口通用调用（未生成的接口也能调）

```go
executor, _ := alipay.NewGenericExecuteApi(configUtil)
result, apiErr := executor.Execute("/v3/alipay/trade/query", "GET",
	&alipay.OpenApiGenericRequest{
		QueryParams: map[string][]string{"out_trade_no": {"123"}},
	})
```

> **业务码判定**：SDK 对齐 PHP 行为，HTTP 2xx 即视为调用成功，不解析响应体 `code`；
> 退款等资金写操作必须自行判定业务码，可用 `alipay.IsBizSuccess(code)`（`code == "10000"` 为成功）。

## 页面类接口（V2 网关兼容）

### App 支付（sdkExecute，返回给客户端的 orderStr）

```go
executor, _ := alipay.NewGenericExecuteApi(configUtil)

orderStr, err := executor.SdkExecute("alipay.trade.app.pay",
	map[string]interface{}{
		"biz_content": map[string]interface{}{
			"out_trade_no": "20240101123456",
			"total_amount": "0.01",
			"subject":      "测试商品",
		},
	}, "", "", nil)
```

### 手机网站 / 电脑网站支付（pageExecute）

```go
// GET：返回带签名的跳转 URL
payUrl, err := executor.PageExecute("alipay.trade.wap.pay", "GET", bizParams, "", "", nil)

// POST：返回自动提交的表单 HTML
formHtml, err := executor.PageExecute("alipay.trade.page.pay", "POST", bizParams, "", "", nil)
```

## 异步通知验签

```go
// 从 HTTP 请求解析参数（application/x-www-form-urlencoded）
params := map[string]string{} // r.PostForm / r.Form 转换后

ok, err := alipay.RsaCheckV1(params, alipayPublicKey, false)
if err == nil && ok {
	// 验签通过，处理业务（注意自行做幂等）
	tradeStatus := params["trade_status"]
	_ = tradeStatus
}
```

```go
// 证书模式：验签公钥取自本商户支付宝公钥证书（alipayPublicCertPEM）
ok, err := alipay.RsaCheckV1WithCert(params, alipayPublicCertPEM, rootCertPEM)
```

- `RsaCheckV1`：**公钥模式**支付通知等接口（剔除 `sign`、`sign_type` 与空值后验签，值以 `@` 开头的字段参与签名）
- `RsaCheckV1WithCert`：**证书模式**支付通知等接口，拼接与剔除口径同上；公钥按 `alipay_cert_sn` 分两条路径选定
  （见下）
- `RsaCheckV2`：生活号等应用网关消息（仅剔除 `sign`，`sign_type` 参与签名）

> **证书模式通知的 `alipay_cert_sn` 是可选字段**：
>
> | 通知里的 `alipay_cert_sn` | `RsaCheckV1WithCert` 行为 |
> |---|---|
> | 缺失/为空 | 用**本商户支付宝公钥证书**（`alipayPublicCertPublicKey_RSA2.crt`）内的公钥验签 |
> | 有值 | 按序列号严格定位：先本证书，再根证书链各段；**不命中即拒**（证书过期/被换会显式报错） |
>
> 官方 Java v2 `rsaCertCheckV1`、PHP v2 `rsaCheckV1`、Node v4 `checkNotifySign`、.NET `CertVerifyV1`、
> EasySDK 的通知验签入口**全部不读**该字段，一律用本地支付宝公钥证书公钥；PHP v3
> `getAlipayPublicKeyWithSN` 的注释原话是「如果没有指定 sn，则默认取缓存中的第一个值」。
> 「SN → 证书定位/下载/根证书链校验」那一整套只作用于**同步 API 响应**，官方《自行实现验签》
> 也是把该字段描述为同步响应报文多出来的响应参数；各产品《异步通知说明》参数表通篇未列它，
> 《证书升级指南》只要求「收到通知后用支付宝公钥证书做验签」。
>
> 第二条路径（有值即严格比对）是**有意严于** Java/.NET/Node 的偏离，对齐官方 PHP v3 的
> 「SN 定位不到即抛证书已过期」，用于证书轮换后的主动告警。
>
> 该字段**不是**防剥离手段：它本身参与待签串（按 key 升序拼入），从真通知里剥掉它签名立刻对不上，
> 自拼一条不带它的通知又因无私钥同样对不上——要求字段必填只会把合法通知判成伪造。
> 2026-10-23 曾有生产事故：支付宝推送的通知未带该字段，SDK 强校验导致回调 100% 验签失败。
>
> **模式判定**：用哪个入口取决于**本应用在开放平台配置的加签方式**，不能由通知里有没有
> `alipay_cert_sn` 反推。若平台侧实为公钥模式，请改用 `RsaCheckV1`。

> **职责边界**：`RsaCheckV1`/`RsaCheckV1WithCert`/`RsaCheckV2` 只判定签名真伪，不校验业务字段——
> 这与官方 PHP SDK 的职责划分一致。公钥模式下若那把「支付宝公钥」确为全商户共用
> （此说尚无官方原文依据，属待核实，稳妥按共用处理），任何商户的合法通知都能通过验签。
> 验签通过后，调用方必须自行完成：
>
> 1. `app_id` 与自身应用配置一致；
> 2. `out_trade_no`、`total_amount` 与本地订单记录一致（防改单、防跨单冒领）；
> 3. `seller_id`（如使用）与预期收款方一致；
> 4. `trade_status` 属于需要处理的状态，且重复通知幂等；
> 5. 通知来源 URL/域名校验与 `failure` 时返回失败应答（支付宝按策略重发约 25 小时）。

> **待核实：空值字段的拼接口径** 官方 PHP v2 `getCheckSignContent` 不过滤空值（`key=` 会照拼进待签串），
> 本仓库 `GetSignContentForNotify` 跳过空值。通知字段全非空时两者等价，若支付宝推来带空值字段的通知
> 则可能出现假失败。最终口径以官方《自行实现验签》原文为准，核实前维持现有行为。

## 敏感信息加密

配置 `EncryptKey`（开放平台设置的 AES 密钥，base64 编码）后，SDK 自动完成：

- 请求体 AES-128-CBC 加密（`Content-Type: text/plain` + `alipay-encrypt-type: AES` 头）
- 响应体自动解密

## 文件上传

```go
resp, apiErr := openFileApi.Upload(&alipay.UploadFile{FilePath: "./bill.jpg"}, nil)
// 或直接传内容：&alipay.UploadFile{FileName: "bill.jpg", Content: data}
```

## 文件结构

| 路径 | 说明 |
|---|---|
| `alipay_config.go` 等 | 核心 runtime（配置、签名、验签、AES、执行器、异常） |
| `api/` | 全量 API 类（生成，勿手改） |
| `model/` | 全量 Model struct（生成，勿手改） |
| `docs/endpoints.md` | API 端点全表（生成） |
| `tools/generator/` | 代码生成器（从官方 oasSchema.json 生成 api/ 与 model/） |

## 重新生成代码

官方 schema 更新后可重新生成全量代码：

```bash
go run ./tools/generator -schema <oasSchema.json 路径> -out .
go build ./... && go test .
```

## 测试

```bash
go test . -v
```

覆盖：证书 SN 计算（issuer 反序规则）、V3 签名串与 Authorization 格式、响应验签（含失败路径）、AES 加解密往返、httptest 模拟网关全流程（签名→服务端验签→响应签名→客户端验签→解密）、V2 sdkExecute/pageExecute（含公钥模式不输出空证书参数）、异步通知验签 V1/V2（官方通知口径 golden 串、`@` 前缀值参与签名、空值剔除、篡改/错公钥拒绝、V1/V2 剔除集合对照）、证书模式通知验签（命中支付宝公钥证书与根证书链段、缺 `alipay_cert_sn` 用本证书公钥通过、非本证书私钥签仍拒绝、序列号不匹配拒绝、篡改拒绝、缺证书配置报错）。

## 参考

- [支付宝开放平台 V3 协议](https://opendocs.alipay.com/open-v3)
- [alipay-sdk-php-all](https://github.com/alipay/alipay-sdk-php-all)（v3 目录）
