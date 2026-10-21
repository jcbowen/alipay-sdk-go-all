package alipay

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jcbowen/jcbaseGo/component/security"
)

// AlipaySignature 独立签名/验签工具，主要用于：
//   - 支付接口异步通知的验签（rsaCheckV1 / rsaCheckV2）；
//   - 无需完整配置的工具型签名场景。
//
// 对齐 PHP SDK 的 Alipay\OpenAPISDK\Util\AlipaySignature。
type AlipaySignature struct{}

// AloneRsaSign 通用签名方法。
//
// 参数:
//   - data: 待签名内容
//   - privateKey: 商户私钥（裸 base64 串或 PEM 文本）
//   - keyFromFile: true 表示 privateKey 为文件路径
//
// 返回值:
//   - string: base64 签名值
//   - error: 私钥格式错误时返回错误（当前仅支持 RSA2）
//
// 使用示例:
//
//	sign, err := alipay.AloneRsaSign("content", privateKey, false)
func AloneRsaSign(data, privateKey string, keyFromFile bool) (string, error) {
	return security.RSASign(data, privateKey, keyFromFile)
}

// RsaSign 对参数集合进行 RSA2 签名（按键名升序拼接后签名）。
//
// 参数:
//   - params: 待签名参数集合
//   - privateKey: 商户私钥
//   - keyFromFile: true 表示 privateKey 为文件路径
//
// 返回值:
//   - string: base64 签名值
//   - error: 签名失败时返回错误
func RsaSign(params map[string]string, privateKey string, keyFromFile bool) (string, error) {
	return AloneRsaSign(GetSignContent(params), privateKey, keyFromFile)
}

// RsaCheckV1 密钥模式 RSA2 通用验签方法（V1 规则）。
//
// 主要用于支付接口异步通知验签：剔除 sign 与 sign_type 两个参数后，
// 剩余参数按通知口径拼接（仅剔除空值，值以 "@" 开头的字段参与签名）。
//
// 职责边界：本方法只判定签名真伪，不校验 app_id、seller_id、金额与通知 URL，
// 调用方必须自行完成业务侧校验（公钥模式下支付宝公钥全商户共用）。
//
// 参数:
//   - params: 从支付宝接收到的完整参数集合（含 sign）
//   - alipayPublicKey: 支付宝公钥（裸 base64 串或 PEM 文本）
//   - keyFromFile: true 表示 alipayPublicKey 为文件路径
//
// 返回值:
//   - bool: true 验签通过
//   - error: 缺少 sign、公钥错误等异常情况
//
// 使用示例:
//
//	ok, err := alipay.RsaCheckV1(notifyParams, alipayPublicKey, false)
func RsaCheckV1(params map[string]string, alipayPublicKey string, keyFromFile bool) (bool, error) {
	sign, err := extractSign(params)
	if err != nil {
		return false, err
	}
	copied := copyParams(params)
	delete(copied, "sign")
	delete(copied, "sign_type")

	return Verify(GetSignContentForNotify(copied), sign, alipayPublicKey, keyFromFile)
}

// RsaCheckV1WithCert 证书模式 RSA2 异步通知验签（V1 规则）。
//
// 证书模式下通知参数携带 alipay_cert_sn（发起通知所用支付宝公钥证书的序列号，
// 由支付宝证书下载工具计算）：优先匹配支付宝公钥证书序列号，未命中再在根证书的
// 证书链中按序列号查找，取对应证书段公钥验签；匹配不到即拒绝——这正是证书模式
// 相对公钥模式多出来的防「证书过期/被替换」校验。拼接与剔除口径同 RsaCheckV1。
//
// 职责边界同 RsaCheckV1：只判定签名与证书序列号真伪，不校验 app_id、金额与交易状态，
// 调用方必须自行完成业务侧校验。
//
// 参数:
//   - params: 从支付宝接收到的完整参数集合（含 sign、alipay_cert_sn）
//   - alipayPublicCertContent: 支付宝公钥证书内容（PEM）
//   - rootCertContent: 支付宝根证书内容（PEM，可含多段证书）
//
// 返回值:
//   - bool: true 验签通过
//   - error: 缺少 sign、证书序列号不匹配、证书解析或验签异常
//
// 使用示例:
//
//	ok, err := alipay.RsaCheckV1WithCert(notifyParams, alipayPublicCertPEM, rootCertPEM)
func RsaCheckV1WithCert(params map[string]string, alipayPublicCertContent, rootCertContent string) (bool, error) {
	sign, err := extractSign(params)
	if err != nil {
		return false, err
	}

	pubKeyPEM, err := resolveNotifyCertPublicKey(params["alipay_cert_sn"], alipayPublicCertContent, rootCertContent)
	if err != nil {
		return false, err
	}

	copied := copyParams(params)
	delete(copied, "sign")
	delete(copied, "sign_type")

	return Verify(GetSignContentForNotify(copied), sign, pubKeyPEM, false)
}

// resolveNotifyCertPublicKey 按通知的 alipay_cert_sn 定位验签用支付宝公钥（PEM）。
//
// 先比对支付宝公钥证书，未命中再遍历根证书链各段；两段都不命中时返回带序列号的错误，
// 便于运维判断是证书过期还是配置串了应用。
//
// 参数:
//   - certSN: 通知参数中的 alipay_cert_sn
//   - alipayPublicCertContent: 支付宝公钥证书内容（PEM）
//   - rootCertContent: 根证书内容（PEM，可含多段）
//
// 返回值:
//   - string: 匹配证书段的公钥 PEM
//   - error: 证书缺失、解析失败或序列号不匹配
func resolveNotifyCertPublicKey(certSN, alipayPublicCertContent, rootCertContent string) (string, error) {
	if strings.TrimSpace(alipayPublicCertContent) != "" {
		sn, err := CertSN(alipayPublicCertContent)
		if err != nil {
			return "", fmt.Errorf("解析支付宝公钥证书失败: %w", err)
		}
		if sn == certSN {
			pubKey, err := CertPublicKey(alipayPublicCertContent)
			if err != nil {
				return "", fmt.Errorf("提取支付宝公钥证书公钥失败: %w", err)
			}
			return security.FormatPublicKeyPEM(pubKey), nil
		}
	}

	if strings.TrimSpace(rootCertContent) != "" {
		for _, block := range splitPEMBlocks(rootCertContent, "CERTIFICATE") {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				// 跳过 Go 标准库无法解析的证书段（根证书文件含国密 SM2 段），
				// 这类段不可能与 RSA 通知的 alipay_cert_sn 命中，报错返回会让整条验签失败
				continue
			}
			if certSNFromCertificate(cert) != certSN {
				continue
			}
			der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return "", fmt.Errorf("导出根证书段公钥失败: %w", err)
			}
			return security.FormatPublicKeyPEM(base64.StdEncoding.EncodeToString(der)), nil
		}
	}

	return "", fmt.Errorf("通知证书序列号不匹配（alipay_cert_sn=%s），请更新支付宝公钥证书与根证书", certSN)
}

// RsaCheckV2 密钥模式 RSA2 通用验签方法（V2 规则）。
//
// 主要用于生活号事件消息等发送到应用网关地址的异步信息验签：
// 仅剔除 sign 参数（sign_type 参与签名），剩余参数按通知口径拼接（只剔空值，保留 "@" 值）。
//
// 参数与返回值同 RsaCheckV1。
func RsaCheckV2(params map[string]string, alipayPublicKey string, keyFromFile bool) (bool, error) {
	sign, err := extractSign(params)
	if err != nil {
		return false, err
	}
	copied := copyParams(params)
	delete(copied, "sign")

	return Verify(GetSignContentForNotify(copied), sign, alipayPublicKey, keyFromFile)
}

// Verify 通用验签方法。
//
// 参数:
//   - data: 待验签字符串
//   - sign: base64 签名值
//   - alipayPublicKey: 支付宝公钥（裸 base64 串或 PEM 文本）
//   - keyFromFile: true 表示 alipayPublicKey 为文件路径
//
// 返回值:
//   - bool: true 验签通过
//   - error: 公钥格式错误时返回错误
func Verify(data, sign, alipayPublicKey string, keyFromFile bool) (bool, error) {
	return security.RSAVerify(data, sign, alipayPublicKey, keyFromFile)
}

// GetSignContent 获取请求侧签名字符串：按键名升序拼接为 "k1=v1&k2=v2"。
//
// 空值与以 "@" 开头的参数（"@文件路径" 上传标记）不参与拼接，对齐 PHP 请求签名行为；
// 仅用于请求签名，异步通知验签请用 GetSignContentForNotify。
//
// 参数:
//   - params: 参数集合
//
// 返回值:
//   - string: 拼接后的签名字符串
func GetSignContent(params map[string]string) string {
	return buildSignContent(params, true)
}

// GetSignContentForNotify 获取异步通知验签侧的待签串：按键名升序拼接，仅剔除空值。
//
// 对齐支付宝官方通知验签口径：值以 "@" 开头的字段照常参与签名
// （如 subject="@团购订单"），剔除集合由调用方（RsaCheckV1/V2）决定。
//
// 参数:
//   - params: 已剔除相应参数的通知参数集合
//
// 返回值:
//   - string: 拼接后的待验签字符串
func GetSignContentForNotify(params map[string]string) string {
	return buildSignContent(params, false)
}

// buildSignContent 按键名升序拼接非空参数；dropAtPrefixed 为 true 时同时剔除值以 "@" 开头的参数。
func buildSignContent(params map[string]string, dropAtPrefixed bool) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	i := 0
	for _, k := range keys {
		v := params[k]
		if strings.TrimSpace(v) == "" {
			continue
		}
		if dropAtPrefixed && strings.HasPrefix(v, "@") {
			continue
		}
		if i > 0 {
			sb.WriteString("&")
		}
		sb.WriteString(k + "=" + v)
		i++
	}
	return sb.String()
}

// extractSign 从参数集合中提取 sign，缺失时返回错误。
func extractSign(params map[string]string) (string, error) {
	sign := params["sign"]
	if strings.TrimSpace(sign) == "" {
		return "", errors.New("待验签参数中缺少 sign 字段")
	}
	return sign, nil
}

// copyParams 复制参数集合
func copyParams(params map[string]string) map[string]string {
	copied := make(map[string]string, len(params))
	for k, v := range params {
		copied[k] = v
	}
	return copied
}
