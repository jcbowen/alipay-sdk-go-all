package alipay

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"crypto/x509/pkix"
)

// AntCertificationUtil 证书工具，提供支付宝证书序列号（certSN）计算与公钥提取能力。
//
// 算法对齐 PHP SDK 的 Alipay\OpenAPISDK\Util\AntCertificationUtil：
// certSN = md5(issuer 反序拼接串 + serialNumber 十进制串)，
// 其中 issuer 拼接格式为 "C=CN,O=Alipay,CN=xxx"（逗号分隔、等号连接）。
//
// 使用示例：
//
//	sn, err := alipay.CertSN(certContent)
//	rootSN, err := alipay.RootCertSN(rootCertContent)
//	pubKey, err := alipay.CertPublicKey(certContent)
type AntCertificationUtil struct{}

// CertSN 从证书内容中提取应用/支付宝公钥证书序列号。
//
// 参数:
//   - certContent: PEM 格式证书内容字符串
//
// 返回值:
//   - string: 证书序列号（issuer 拼接串与序列号串联后的 MD5 hex）
//   - error: 证书解析失败时返回错误
//
// 使用示例:
//
//	sn, err := alipay.CertSN(string(appCertPEM))
func CertSN(certContent string) (string, error) {
	cert, err := ParseCertificate([]byte(certContent))
	if err != nil {
		return "", err
	}
	return certSNFromCertificate(cert), nil
}

// RootCertSN 提取根证书序列号。
//
// 根证书文件可能包含多段证书，逐段计算 SN 后以 "_" 连接；
// 仅统计签名算法为 sha1WithRSAEncryption 或 sha256WithRSAEncryption 的证书段，
// 与 PHP SDK 行为一致。Go 标准库无法解析的证书段（如支付宝根证书里的国密 SM2 段）
// 本就不参与 SN 计算，直接跳过而非报错，否则一份合法根证书会被判成不可解析。
//
// 参数:
//   - certContent: PEM 格式根证书内容（可含多段 -----BEGIN CERTIFICATE-----）
//
// 返回值:
//   - string: 根证书序列号串（多段以 "_" 连接，仅含可用的 RSA 证书段）
//   - error: 找不到 PEM 段，或没有任何可解析的 RSA 证书段（视为内容非法）
//
// 使用示例:
//
//	rootSN, err := alipay.RootCertSN(string(rootCertPEM))
func RootCertSN(certContent string) (string, error) {
	blocks := splitPEMBlocks(certContent, "CERTIFICATE")
	if len(blocks) == 0 {
		return "", errors.New("根证书内容中未找到 CERTIFICATE PEM 段")
	}

	var sns []string
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		// 对齐 PHP：仅统计 sha1WithRSAEncryption / sha256WithRSAEncryption
		switch cert.SignatureAlgorithm {
		case x509.SHA1WithRSA, x509.SHA256WithRSA:
			sns = append(sns, certSNFromCertificate(cert))
		}
	}
	// 全段都取不到 SN 说明内容不是根证书（错传成应用证书或纯文本），须继续拒绝
	if len(sns) == 0 {
		return "", errors.New("根证书中没有可解析的 RSA 证书段（sha1WithRSA/sha256WithRSA）")
	}
	return strings.Join(sns, "_"), nil
}

// CertPublicKey 从证书内容中提取公钥的 base64 字符串（不含 PEM 头尾）。
//
// 参数:
//   - certContent: PEM 格式证书内容字符串
//
// 返回值:
//   - string: base64 编码的公钥内容（可配合 FormatPublicKeyPEM 使用）
//   - error: 证书解析失败时返回错误
//
// 使用示例:
//
//	pubKey, err := alipay.CertPublicKey(certContent)
func CertPublicKey(certContent string) (string, error) {
	cert, err := ParseCertificate([]byte(certContent))
	if err != nil {
		return "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("导出证书公钥失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pubDER), nil
}

// ParseCertificate 解析单个 PEM 证书内容为 *x509.Certificate。
//
// 参数:
//   - certBytes: PEM 证书内容字节
//
// 返回值:
//   - *x509.Certificate: 解析后的证书对象
//   - error: PEM 块缺失或解析失败时返回错误
func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, errors.New("证书格式错误：未找到 PEM 块")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("证书解析失败: %w", err)
	}
	return cert, nil
}

// certSNFromCertificate 按支付宝规则计算单张证书的序列号：
// md5(issuer 反序拼接串 + 十进制序列号)。
//
// issuer 拼接说明：PHP openssl_x509_parse 输出的 issuer 为 DER 逆序，
// 经 array_reverse 后恢复为 DER 正序（即 C=xx,O=xx,CN=xx），
// 因此此处直接按 x509 RDNSequence 正序遍历即可对齐。
func certSNFromCertificate(cert *x509.Certificate) string {
	return md5Hex(issuerString(cert.Issuer.ToRDNSequence()) + cert.SerialNumber.String())
}

// issuerString 将 RDNSequence 拼接为支付宝约定的 issuer 字符串。
//
// 对齐 PHP openssl_x509_parse + array_reverse：
// 先按 DER 正序收集（同键后值覆盖、保持首次出现位置），再整体反序拼接。
// 实际结果形如 "CN=Alipay CA,OU=Alipay US,O=Alipay,C=CN"。
func issuerString(seq pkix.RDNSequence) string {
	order := make([]string, 0, len(seq))
	value := make(map[string]string)
	for _, rdn := range seq {
		for _, atv := range rdn {
			key := atvTypeString(atv.Type)
			if _, exists := value[key]; !exists {
				order = append(order, key)
			}
			value[key] = fmt.Sprintf("%v", atv.Value)
		}
	}

	// 整体反序（对齐 PHP array_reverse）
	parts := make([]string, 0, len(order))
	for i := len(order) - 1; i >= 0; i-- {
		key := order[i]
		parts = append(parts, key+"="+value[key])
	}
	return strings.Join(parts, ",")
}

// atvTypeString 将 OID 转换为支付宝惯用的 DN 键名（C/O/CN/OU/ST/L/SN/GN/emailAddress/serialNumber 等）。
func atvTypeString(oid []int) string {
	if s, ok := dnOIDNames[x509OIDKey(oid)]; ok {
		return s
	}
	// 未知 OID 退化为点分数字串
	parts := make([]string, len(oid))
	for i, v := range oid {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ".")
}

// dnOIDKey 将 OID 转为用于查表的键
func x509OIDKey(oid []int) string {
	parts := make([]string, len(oid))
	for i, v := range oid {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ".")
}

// dnOIDNames 常用 DN 属性 OID → 键名映射（与 openssl_x509_parse 输出对齐）
var dnOIDNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.4":                    "SN",
	"2.5.4.42":                   "GN",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.9":                    "street",
	"2.5.4.17":                   "postalCode",
	"1.2.840.113549.1.9.8":       "unstructuredName",
	"1.2.840.113549.1.9.2":       "unstructuredAddress",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
}

// splitPEMBlocks 拆分内容中所有指定类型的 PEM 块
func splitPEMBlocks(content, blockType string) []*pem.Block {
	var blocks []*pem.Block
	rest := []byte(content)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == blockType {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

// md5Hex 计算字符串的 MD5 并返回 hex 小写串
func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
