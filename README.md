# alipay-sdk-go-all

支付宝开放平台 **V3 协议** Go 语言 SDK，对齐官方 [alipay-sdk-php-all](https://github.com/alipay/alipay-sdk-php-all) 仓库 v3 版本的核心能力与全量 API。

- 全量 API：由代码生成器从官方 `oasSchema.json` 生成 **2722 个 Model** 与 **746 个 API 方法**
- V3 协议：`ALIPAY-SHA256withRSA` 请求签名、响应验签、证书序列号（certSN/rootCertSN）、敏感信息 AES 加解密
- V2 兼容：`pageExecute` / `sdkExecute` 支持 App 支付、手机网站支付、电脑网站支付等页面类接口
- 异步通知：`RsaCheckV1` / `RsaCheckV2` 通用验签
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

- `RsaCheckV1`：支付通知等接口（剔除 `sign`、`sign_type` 后验签）
- `RsaCheckV2`：生活号等应用网关消息（仅剔除 `sign`）

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

覆盖：证书 SN 计算（issuer 反序规则）、V3 签名串与 Authorization 格式、响应验签（含失败路径）、AES 加解密往返、httptest 模拟网关全流程（签名→服务端验签→响应签名→客户端验签→解密）、V2 sdkExecute/pageExecute、异步通知验签 V1/V2。

## 参考

- [支付宝开放平台 V3 协议](https://opendocs.alipay.com/open-v3)
- [alipay-sdk-php-all](https://github.com/alipay/alipay-sdk-php-all)（v3 目录）
