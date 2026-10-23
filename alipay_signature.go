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
// 调用方必须自行完成业务侧校验（公钥模式下「支付宝公钥全商户共用」一说尚缺官方原文
// 依据，仅为本仓库既有认知，稳妥起见按共用处理）。
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
// 待签串拼接与剔除口径同 RsaCheckV1；验签公钥按通知的 alipay_cert_sn 分两条路径选定：
//
//  1. alipay_cert_sn 缺失或为空 —— 官方主路径，直接用本商户支付宝公钥证书
//     （alipayPublicCertContent）内的公钥验签。这不是「兜底」也不是「回落到公钥模式」：
//     这把钥匙仍是本应用专属的支付宝公钥证书公钥，商户维度绑定没丢。
//     依据：官方 Java v2 rsaCertCheckV1、PHP v2 rsaCheckV1、Node v4 checkNotifySign、
//     .NET CertVerifyV1、EasySDK 的通知验签入口全部不读 alipay_cert_sn，一律用本地
//     支付宝公钥证书公钥；PHP v3 getAlipayPublicKeyWithSN 注释原话「如果没有指定 sn，
//     则默认取缓存中的第一个值」；《自行实现验签》把该字段描述为同步响应报文里多出来的
//     响应参数，各产品《异步通知说明》参数表通篇未列它，《证书升级指南》也只要求
//     「收到请求报文后用支付宝公钥证书做验签」。
//     把响应侧的 SN 语义搬到通知侧、要求该字段必填，会把支付宝未带该字段的合法通知
//     整批判成验签失败（2026-10-23 生产实锤）。
//  2. alipay_cert_sn 有值 —— 按序列号严格定位（先本证书，再根证书链各段），不命中即拒。
//     这一处有意严于 Java/.NET/Node（它们拿到 SN 也不比对），对齐官方 PHP v3
//     getAlipayPublicKeyWithSN 与 EasySDK getAlipayPublicKey(sn) 的「SN 定位不到即抛证书已过期」，
//     用途是证书轮换/过期后的主动告警，而不是防伪造。
//
// 两条路径不可混谈：alipay_cert_sn 本身参与待签串（它是通知参数之一，按 key 升序拼入），
// 从真通知里剥掉它签名立刻对不上，自拼一条不带它的通知又因无私钥同样对不上——
// 「缺字段即拒」防的是一个会自毁的伪造，代价是把官方文档描述的常态判成攻击。
//
// 模式判定口径：用本方法还是 RsaCheckV1，取决于本应用配置的加签方式，不能由通知
// 字段反推。平台侧配置为公钥模式的应用应改用 RsaCheckV1。
//
// 职责边界同 RsaCheckV1：只判定签名与证书序列号真伪，不校验 app_id、金额与交易状态，
// 调用方必须自行完成业务侧校验。
//
// 参数:
//   - params: 从支付宝接收到的完整参数集合（含 sign；alipay_cert_sn 可有可无）
//   - alipayPublicCertContent: 支付宝公钥证书内容（PEM）
//   - rootCertContent: 支付宝根证书内容（PEM，可含多段证书；仅当 alipay_cert_sn 有值时参与定位）
//
// 返回值:
//   - bool: true 验签通过
//   - error: 缺少 sign、证书缺失或解析失败、证书序列号不匹配、验签异常
//
// 使用示例:
//
//	ok, err := alipay.RsaCheckV1WithCert(notifyParams, alipayPublicCertPEM, rootCertPEM)
func RsaCheckV1WithCert(params map[string]string, alipayPublicCertContent, rootCertContent string) (bool, error) {
	sign, err := extractSign(params)
	if err != nil {
		return false, err
	}

	copied := copyParams(params)
	delete(copied, "sign")
	delete(copied, "sign_type")

	certSN := strings.TrimSpace(params["alipay_cert_sn"])
	verifyKey, err := notifyVerifyKey(certSN, alipayPublicCertContent, rootCertContent)
	if err != nil {
		return false, err
	}

	return Verify(GetSignContentForNotify(copied), sign, verifyKey, false)
}

// notifyVerifyKey 选定证书模式通知的验签公钥，两条路径互不混用。
//
// 参数:
//   - certSN: 通知里的 alipay_cert_sn，已 TrimSpace，可为空
//   - alipayPublicCertContent: 支付宝公钥证书内容（PEM）
//   - rootCertContent: 根证书内容（PEM，可含多段）
//
// 返回值:
//   - string: 验签用公钥（裸 base64 DER 或 PEM）
//   - error: 证书缺失、解析失败或序列号不匹配
//
// 说明:
//   - certSN 为空 → 本商户支付宝公钥证书公钥，官方通知验签主路径（详见 RsaCheckV1WithCert）；
//   - certSN 有值 → 按序列号严格定位，不命中即拒。
func notifyVerifyKey(certSN, alipayPublicCertContent, rootCertContent string) (string, error) {
	if certSN == "" {
		if strings.TrimSpace(alipayPublicCertContent) == "" {
			return "", errors.New("缺少支付宝公钥证书内容")
		}
		pubKey, err := CertPublicKey(alipayPublicCertContent)
		if err != nil {
			return "", fmt.Errorf("提取支付宝公钥证书公钥失败: %w", err)
		}
		return pubKey, nil
	}
	return resolveNotifyCertPublicKey(certSN, alipayPublicCertContent, rootCertContent)
}

// resolveNotifyCertPublicKey 按通知的 alipay_cert_sn 严格定位验签用支付宝公钥（PEM）。
//
// 先比对支付宝公钥证书，未命中再遍历根证书链各段；两段都不命中时返回带序列号的错误，
// 便于运维判断是证书过期还是配置串了应用。仅 RsaCheckV1WithCert 在 certSN 非空时调用，
// 空 SN 走证书公钥主路径，不进本函数（见该函数注释的两种路径划分）。
//
// 参数:
//   - certSN: 通知参数中的 alipay_cert_sn（非空）
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
// 已核实（README「空值字段的拼接口径」有各家 SDK 对照表）：官方文档《自行实现验签》只说
// 「除去 sign、sign_type，通知返回的参数均为待验签参数」，未规定空值处理；Java v2
// getSignCheckContentV1 与 .NET GetSignContent 剔除空/空白值，PHP v2/v3 getSignContent 与
// Node notifyRSACheck 保留（且 PHP 反而剔除 @ 前缀值）。本实现取 Java/.NET 口径：剔除空值、
// 保留 @ 值。两套口径互斥，能长期共存说明网关实际不下发空值字段，故维持现状。
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
