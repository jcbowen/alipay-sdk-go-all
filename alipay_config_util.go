package alipay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jcbowen/jcbaseGo/component/security"
)

// AuthScheme V3 签名的 Authorization 认证方案前缀
const AuthScheme = "ALIPAY-SHA256withRSA"

// AlipayConfigUtil 核心工具：V3 请求签名、响应验签、敏感信息 AES 加解密。
//
// 对齐 PHP SDK 的 Alipay\OpenAPISDK\Util\AlipayConfigUtil，
// 通过 NewAlipayConfigUtil 创建，内部完成证书解析与支付宝公钥缓存。
//
// 使用示例：
//
//	configUtil, err := alipay.NewAlipayConfigUtil(cfg)
//	if err != nil {
//	    panic(err)
//	}
type AlipayConfigUtil struct {
	serverUrl             string
	appId                 string
	privateKey            string // 已包装为 PEM 的私钥文本
	privateKeyFilePath    string
	alipayPublicKey       string // 已包装为 PEM 的支付宝公钥文本
	alipayPublicKeyFilePath string
	rootCertSN            string
	appCertSN             string
	encryptType           string
	encryptKey            string

	// cachedAlipayPublicKey 证书模式：支付宝公钥证书序列号 → PEM 公钥文本
	cachedAlipayPublicKey map[string]string

	mu          sync.Mutex
	privateKeyCached *rsa.PrivateKey // 惰性解析缓存
	publicKeyCached  *rsa.PublicKey  // 公钥模式惰性解析缓存
}

// NewAlipayConfigUtil 由 AlipayConfig 构建配置工具。
//
// 证书模式下会解析三类证书：根证书（计算 rootCertSN）、应用证书（appCertSN）、
// 支付宝公钥证书（缓存 序列号→公钥 映射，用于响应验签）。
// 证书内容字段（*CertContent）优先于证书路径字段（*CertPath）。
//
// 参数:
//   - config: 配置模型，不能为 nil
//
// 返回值:
//   - *AlipayConfigUtil: 配置工具
//   - error: 证书文件读取失败或证书解析失败时返回错误
//
// 使用示例:
//
//	cfg := &alipay.AlipayConfig{AppId: "...", PrivateKey: "...", EncryptKey: "..."}
//	configUtil, err := alipay.NewAlipayConfigUtil(cfg)
func NewAlipayConfigUtil(config *AlipayConfig) (*AlipayConfigUtil, error) {
	if config == nil {
		return nil, errors.New("AlipayConfig 不能为空")
	}

	u := &AlipayConfigUtil{
		serverUrl:             strings.TrimSpace(config.ServerUrl),
		appId:                 config.AppId,
		privateKeyFilePath:    config.PrivateKeyFilePath,
		alipayPublicKeyFilePath: config.AlipayPublicKeyFilePath,
		encryptType:           config.EncryptType,
		encryptKey:            config.EncryptKey,
		cachedAlipayPublicKey: make(map[string]string),
	}
	if u.serverUrl == "" {
		u.serverUrl = DefaultServerUrl
	}
	if u.encryptType == "" {
		u.encryptType = EncryptTypeAES
	}

	// 私钥：裸串包装为 PEM（与 PHP wordwrap 逻辑一致），文件路径延迟到签名时读取
	if strings.TrimSpace(config.PrivateKey) != "" {
		u.privateKey = security.FormatPrivateKeyPEM(config.PrivateKey)
	}

	// 支付宝公钥：裸串包装为 PEM
	if strings.TrimSpace(config.AlipayPublicKey) != "" {
		u.alipayPublicKey = security.FormatPublicKeyPEM(config.AlipayPublicKey)
	}

	// 未配置支付宝公钥证书 → 公钥模式，提前返回跳过证书初始化（对齐 PHP）
	if strings.TrimSpace(config.AlipayPublicCertContent) == "" &&
		strings.TrimSpace(config.AlipayPublicCertPath) == "" {
		return u, nil
	}

	// 根证书
	rootCertContent := config.RootCertContent
	if strings.TrimSpace(rootCertContent) == "" {
		content, err := os.ReadFile(config.RootCertPath)
		if err != nil {
			return nil, fmt.Errorf("读取根证书失败: %w", err)
		}
		rootCertContent = string(content)
	}
	rootSN, err := RootCertSN(rootCertContent)
	if err != nil {
		return nil, err
	}
	u.rootCertSN = rootSN

	// 应用证书
	appCertContent := config.AppCertContent
	if strings.TrimSpace(appCertContent) == "" {
		content, err := os.ReadFile(config.AppCertPath)
		if err != nil {
			return nil, fmt.Errorf("读取应用证书失败: %w", err)
		}
		appCertContent = string(content)
	}
	appSN, err := CertSN(appCertContent)
	if err != nil {
		return nil, err
	}
	u.appCertSN = appSN

	// 支付宝公钥证书：缓存 序列号→公钥
	alipayCertContent := config.AlipayPublicCertContent
	if strings.TrimSpace(alipayCertContent) == "" {
		content, err := os.ReadFile(config.AlipayPublicCertPath)
		if err != nil {
			return nil, fmt.Errorf("读取支付宝公钥证书失败: %w", err)
		}
		alipayCertContent = string(content)
	}
	alipayCertSN, err := CertSN(alipayCertContent)
	if err != nil {
		return nil, err
	}
	pubKey, err := CertPublicKey(alipayCertContent)
	if err != nil {
		return nil, err
	}
	u.cachedAlipayPublicKey[alipayCertSN] = security.FormatPublicKeyPEM(pubKey)

	return u, nil
}

// GetServerUrl 返回网关地址。
func (u *AlipayConfigUtil) GetServerUrl() string { return u.serverUrl }

// GetAppId 返回应用 ID。
func (u *AlipayConfigUtil) GetAppId() string { return u.appId }

// GetAppCertSN 返回应用证书序列号（公钥模式为空串）。
func (u *AlipayConfigUtil) GetAppCertSN() string { return u.appCertSN }

// GetRootCertSN 返回根证书序列号（公钥模式为空串）。
func (u *AlipayConfigUtil) GetRootCertSN() string { return u.rootCertSN }

// GetEncryptType 返回敏感信息加密算法类型。
func (u *AlipayConfigUtil) GetEncryptType() string { return u.encryptType }

// GetEncryptKey 返回敏感信息加密密钥。
func (u *AlipayConfigUtil) GetEncryptKey() string { return u.encryptKey }

// IsNeedSign 判断是否需要签名（未配置私钥时不需要）。
func (u *AlipayConfigUtil) IsNeedSign() bool {
	return strings.TrimSpace(u.privateKey) != "" || strings.TrimSpace(u.privateKeyFilePath) != ""
}

// IsEncrypt 判断是否需要敏感信息加密（未配置 encryptKey 时不需要）。
//
// 返回值:
//   - bool: true 表示请求与响应需要 AES 加解密
//   - error: encryptType 配置了不支持的非 AES 算法时返回错误
func (u *AlipayConfigUtil) IsEncrypt() (bool, error) {
	if strings.TrimSpace(u.encryptKey) == "" {
		return false, nil
	}
	if u.encryptType != EncryptTypeAES {
		return false, fmt.Errorf("当前不支持该算法类型：encryptType=%s", u.encryptType)
	}
	return true, nil
}

// Sign 计算 V3 签名并写入 headers 的 Authorization 头。
//
// 待签串构造（对齐 PHP）：
//
//	authString = app_id={appId}[,app_cert_sn={sn}],nonce={uuid},timestamp={millis}
//	content    = authString\n + httpMethod\n + httpRequestUri\n + requestBody\n + [appAuthToken\n]
//
// 其中 requestBody 为空时仅保留换行符；appAuthToken 取自 headers 的
// alipay-app-auth-token，存在时才附加其值与换行符。
//
// 参数:
//   - httpMethod: HTTP 方法（GET/POST/PUT/DELETE）
//   - httpRequestUri: 请求 URI（含查询串）
//   - httpRequestBody: 请求体（未加密前的 JSON 文本）
//   - headerParams: 请求头集合（写入 Authorization）
//
// 返回值:
//   - error: 私钥解析或签名失败时返回错误
func (u *AlipayConfigUtil) Sign(httpMethod, httpRequestUri, httpRequestBody string, headerParams http.Header) error {
	appAuthToken := firstHeaderValue(headerParams, "alipay-app-auth-token")
	nonce := CreateUUID()
	timestamp := GetCurrentMilis()

	authString := "app_id=" + u.appId
	if u.appCertSN != "" {
		authString += ",app_cert_sn=" + u.appCertSN
	}
	authString += ",nonce=" + nonce + ",timestamp=" + timestamp

	content := authString + "\n" + httpMethod + "\n" + httpRequestUri + "\n"
	if strings.TrimSpace(httpRequestBody) != "" {
		content += httpRequestBody
	}
	content += "\n"
	if appAuthToken != "" {
		content += appAuthToken + "\n"
	}

	if u.IsNeedSign() {
		sign, err := u.GenerateSign(content)
		if err != nil {
			return err
		}
		headerParams.Set("Authorization", AuthScheme+" "+authString+",sign="+sign)
	} else {
		headerParams.Set("Authorization", AuthScheme+" "+authString)
	}
	return nil
}

// GenerateSign 使用商户私钥对待签名内容进行 SHA256withRSA 签名。
//
// 参数:
//   - content: 待签名字符串
//
// 返回值:
//   - string: base64 编码签名值
//   - error: 私钥解析失败或签名失败时返回错误
func (u *AlipayConfigUtil) GenerateSign(content string) (string, error) {
	priKey, err := u.loadPrivateKey()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, priKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("RSA签名失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify 验证支付宝返回内容的签名。
//
// 证书模式按 alipayCertSN 从缓存取支付宝公钥；公钥模式直接使用配置的公钥。
// 待验串构造（对齐 PHP）：
//
//	timestamp\n + nonce\n + content\n （content 为空时仅保留换行符）
//
// 参数:
//   - content: 待验签的响应体
//   - sign: base64 签名值（alipay-signature 头）
//   - alipayCertSN: 支付宝公钥证书序列号（alipay-sn 头，公钥模式忽略）
//   - timestamp: 时间戳（alipay-timestamp 头）
//   - nonce: 随机串（alipay-nonce 头）
//
// 返回值:
//   - bool: true 验签通过
//   - error: 支付宝公钥配置错误或公钥证书不存在时返回错误
func (u *AlipayConfigUtil) Verify(content, sign, alipayCertSN, timestamp, nonce string) (bool, error) {
	var pubKeyPEM string
	if u.appCertSN != "" {
		// 证书模式
		pubKeyPEM = u.GetAlipayPublicKeyWithSN(alipayCertSN)
		if pubKeyPEM == "" {
			return false, errors.New("支付宝公钥证书[" + alipayCertSN + "]已过期，请重新下载最新支付宝公钥证书并替换原证书文件")
		}
	} else if u.alipayPublicKeyFilePath == "" {
		pubKeyPEM = u.alipayPublicKey
	} else {
		content, err := os.ReadFile(u.alipayPublicKeyFilePath)
		if err != nil {
			return false, fmt.Errorf("读取支付宝公钥文件失败: %w", err)
		}
		pubKeyPEM = string(content)
	}
	if pubKeyPEM == "" {
		if !u.IsNeedSign() {
			return true, nil
		}
		return false, errors.New("支付宝RSA公钥错误。请检查公钥文件格式是否正确")
	}

	verifyContent := timestamp + "\n" + nonce + "\n"
	if strings.TrimSpace(content) != "" {
		verifyContent += content
	}
	verifyContent += "\n"

	return security.RSAVerify(verifyContent, sign, pubKeyPEM, false)
}

// VerifyResponse 对支付宝响应进行验签。
//
// 参数:
//   - respBody: 响应体
//   - headers: 响应头（alipay-signature / alipay-sn / alipay-timestamp / alipay-nonce）
//   - isCheckSign: true 时仅当 alipay-signature 头存在才验签（对齐 PHP isCheckSign 语义）
//
// 返回值:
//   - error: 验签失败时返回错误（携带响应头与响应体）
func (u *AlipayConfigUtil) VerifyResponse(respBody []byte, headers http.Header, isCheckSign bool) error {
	sign := firstHeaderValue(headers, "alipay-signature")
	if isCheckSign && (strings.TrimSpace(sign) == "" || sign == "null") {
		return nil
	}

	alipaySN := firstHeaderValue(headers, "alipay-sn")
	timestamp := firstHeaderValue(headers, "alipay-timestamp")
	nonce := firstHeaderValue(headers, "alipay-nonce")

	// 签名值非合法 base64 或为空时直接视为验签失败（对齐 PHP openssl_verify 返回 false 的路径）
	if decoded, err := base64.StdEncoding.DecodeString(sign); err != nil || len(decoded) == 0 {
		return NewApiException(400,
			fmt.Sprintf("sign check fail: check Sign and Data Fail! [sign=%s, respBody=%s]", sign, string(respBody)),
			headers, string(respBody))
	}

	verify, err := u.Verify(string(respBody), sign, alipaySN, timestamp, nonce)
	if err != nil {
		return err
	}
	if !verify {
		return NewApiException(400,
			fmt.Sprintf("sign check fail: check Sign and Data Fail! [sign=%s, respBody=%s]", sign, string(respBody)),
			headers, string(respBody))
	}
	return nil
}

// Encrypt 对敏感信息明文进行 AES-128-CBC 加密（PKCS7 填充，base64 输出）。
//
// 参数:
//   - plainText: 明文（非标量类字符串将原样返回）
//
// 返回值:
//   - string: base64 密文；encryptKey 未配置或明文为空时原样返回
//   - error: encryptType 不支持或加密失败时返回错误
func (u *AlipayConfigUtil) Encrypt(plainText string) (string, error) {
	need, err := u.IsEncrypt()
	if err != nil {
		return "", err
	}
	if !need {
		return plainText, nil
	}
	if strings.TrimSpace(plainText) == "" {
		return "", nil
	}

	keyBytes, err := base64.StdEncoding.DecodeString(u.encryptKey)
	if err != nil {
		return "", fmt.Errorf("AES加密失败，encryptKey 不是合法的 base64: %w", err)
	}

	out, err := encryptAES(plainText, string(keyBytes))
	if err != nil {
		return "", fmt.Errorf("AES加密失败，keySize=%d。%w", len(keyBytes), err)
	}
	return out, nil
}

// Decrypt 对支付宝返回的密文进行 AES-128-CBC 解密。
//
// 参数:
//   - cipherText: base64 密文
//
// 返回值:
//   - string: 解密后的明文；encryptKey 未配置时原样返回
//   - error: 解密失败时返回错误
func (u *AlipayConfigUtil) Decrypt(cipherText string) (string, error) {
	need, err := u.IsEncrypt()
	if err != nil {
		return "", err
	}
	if !need {
		return cipherText, nil
	}
	if strings.TrimSpace(cipherText) == "" {
		return "", nil
	}

	keyBytes, err := base64.StdEncoding.DecodeString(u.encryptKey)
	if err != nil {
		return "", fmt.Errorf("AES解密失败，encryptKey 不是合法的 base64: %w", err)
	}

	out, err := decryptAES(cipherText, string(keyBytes))
	if err != nil {
		return "", fmt.Errorf("AES解密失败，keySize=%d。%w", len(keyBytes), err)
	}
	return out, nil
}

// GetAlipayPublicKeyWithSN 按支付宝公钥证书序列号从缓存取公钥 PEM 文本。
//
// 参数:
//   - sn: 支付宝公钥证书序列号，为空时返回缓存中的第一个
//
// 返回值:
//   - string: PEM 公钥文本；缓存为空返回空串
func (u *AlipayConfigUtil) GetAlipayPublicKeyWithSN(sn string) string {
	if strings.TrimSpace(sn) == "" {
		for _, v := range u.cachedAlipayPublicKey {
			return v
		}
		return ""
	}
	return u.cachedAlipayPublicKey[sn]
}

// loadPrivateKey 惰性解析并缓存商户私钥。
func (u *AlipayConfigUtil) loadPrivateKey() (*rsa.PrivateKey, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.privateKeyCached != nil {
		return u.privateKeyCached, nil
	}

	keyText := u.privateKey
	if u.privateKeyFilePath != "" {
		content, err := os.ReadFile(u.privateKeyFilePath)
		if err != nil {
			return nil, fmt.Errorf("读取私钥文件失败: %w", err)
		}
		keyText = string(content)
	}
	if strings.TrimSpace(keyText) == "" {
		return nil, errors.New("您使用的私钥格式错误，请检查RSA私钥配置")
	}

	key, err := security.ParseRSAPrivateKey([]byte(keyText))
	if err != nil {
		return nil, errors.New("您使用的私钥格式错误，请检查RSA私钥配置")
	}
	u.privateKeyCached = key
	return key, nil
}

// CreateUUID 生成随机 UUID（8-4-4-4-12 格式），用于 nonce 与 alipay-request-id。
//
// 返回值:
//   - string: 随机 UUID 字符串
//
// 使用示例:
//
//	nonce := alipay.CreateUUID()
func CreateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// GetCurrentMilis 返回当前毫秒级时间戳字符串。
//
// 返回值:
//   - string: 毫秒时间戳（如 1700000000000）
func GetCurrentMilis() string {
	return fmt.Sprintf("%d", time.Now().UnixMilli())
}

// firstHeaderValue 从 http.Header 取指定头第一个值，不存在返回空串。
func firstHeaderValue(headers http.Header, key string) string {
	if headers == nil {
		return ""
	}
	values := http.Header(headers).Values(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

