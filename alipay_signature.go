package alipay

import (
	"errors"
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
