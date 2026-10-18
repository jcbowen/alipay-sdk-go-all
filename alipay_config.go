// Package alipay 是支付宝开放平台 V3 协议的 Go 语言 SDK 核心包。
//
// 本包对齐官方 alipay-sdk-php-all 仓库 v3 版本的核心能力：
// V3 请求签名与响应验签、证书序列号计算、敏感信息 AES 加解密、
// 通用接口执行器（含 V2 网关 pageExecute/sdkExecute 兼容）。
package alipay

// AlipayConfig 支付宝开放平台配置模型。
//
// 与 PHP SDK 的 Alipay\OpenAPISDK\Util\Model\AlipayConfig 对齐，
// 支持公钥模式与证书模式两种接入方式：
//   - 公钥模式：设置 AlipayPublicKey（或其文件路径），无需证书字段；
//   - 证书模式：设置 AppCert、AlipayPublicCert、RootCert 三类证书（路径或内容二选一，内容优先）。
//
// 使用示例：
//
//	cfg := &alipay.AlipayConfig{
//	    AppId:            "2021000100000000",
//	    PrivateKey:       "MIIEpAIBAAK...",        // 裸私钥串或 PEM 文本
//	    AlipayPublicKey:  "MIIBIjANBgkq...",       // 公钥模式
//	    EncryptKey:       "base64加密密钥",
//	}
type AlipayConfig struct {
	// ServerUrl 网关地址，留空使用默认 https://openapi.alipay.com
	ServerUrl string `json:"server_url,omitempty"`

	// AppId 开放平台上创建的应用 ID（必填）
	AppId string `json:"app_id,omitempty"`

	// PrivateKey 商户私钥（裸 base64 串或 PEM 文本），与 PrivateKeyFilePath 二选一，文件路径优先
	PrivateKey string `json:"private_key,omitempty"`

	// PrivateKeyFilePath 私钥文件路径，优先于 PrivateKey
	PrivateKeyFilePath string `json:"-"`

	// AlipayPublicKey 支付宝公钥字符串（公钥模式下设置），与 AlipayPublicKeyFilePath 二选一
	AlipayPublicKey string `json:"alipay_public_key,omitempty"`

	// AlipayPublicKeyFilePath 支付宝公钥文件路径，优先于 AlipayPublicKey
	AlipayPublicKeyFilePath string `json:"-"`

	// AppCertPath 商户应用公钥证书路径（证书模式下设置）
	AppCertPath string `json:"-"`

	// AlipayPublicCertPath 支付宝公钥证书路径（证书模式下设置）
	AlipayPublicCertPath string `json:"-"`

	// RootCertPath 支付宝根证书路径（证书模式下设置）
	RootCertPath string `json:"-"`

	// AppCertContent 商户应用公钥证书内容字符串，优先于 AppCertPath
	AppCertContent string `json:"-"`

	// AlipayPublicCertContent 支付宝公钥证书内容字符串，优先于 AlipayPublicCertPath
	AlipayPublicCertContent string `json:"-"`

	// RootCertContent 支付宝根证书内容字符串，优先于 RootCertPath
	RootCertContent string `json:"-"`

	// EncryptType 敏感信息对称加密算法类型，当前仅支持 AES，默认 AES
	EncryptType string `json:"encrypt_type,omitempty"`

	// EncryptKey 敏感信息对称加密算法密钥（base64 编码）
	EncryptKey string `json:"encrypt_key,omitempty"`
}

// EncryptTypeAES 敏感信息加密算法常量：AES
const EncryptTypeAES = "AES"

// SignTypeRSA2 签名算法常量：RSA2（SHA256withRSA）
const SignTypeRSA2 = "RSA2"

// DefaultServerUrl 默认网关地址
const DefaultServerUrl = "https://openapi.alipay.com"

// V2GatewayPath V2 兼容网关路径（pageExecute/sdkExecute 使用）
const V2GatewayPath = "/gateway.do"
