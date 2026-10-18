package alipay

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// AlipayLogger SDK 日志器。
//
// 对齐 PHP SDK 的 Alipay\OpenAPISDK\Util\AlipayLogger 分级日志：
// Info（请求信息）、BizResponseInfo（响应信息）、BizError（错误信息）。
// 默认输出到标准错误，可通过 SetLogger 注入自定义 *log.Logger，或 SetLoggerEnabled 关闭。
//
// 使用示例：
//
//	alipay.SetLogger(log.New(os.Stdout, "[alipay] ", log.LstdFlags))
//	alipay.SetLoggerEnabled(false) // 关闭日志
type AlipayLogger struct {
	logger  *log.Logger
	enabled bool
}

// defaultLogger 默认日志器（标准错误、开启）
var defaultLogger = &AlipayLogger{
	logger:  log.New(os.Stderr, "[AlipaySDK] ", log.LstdFlags),
	enabled: true,
}

// SetLogger 设置自定义日志器。
//
// 参数:
//   - l: 标准 log.Logger 实例
func SetLogger(l *log.Logger) {
	defaultLogger.logger = l
}

// SetLoggerEnabled 开启或关闭 SDK 日志。
//
// 参数:
//   - enabled: true 开启（默认），false 关闭
func SetLoggerEnabled(enabled bool) {
	defaultLogger.enabled = enabled
}

// logInfo 记录请求信息：网关 URL、方法、请求体、请求 ID。
func (l *AlipayLogger) logInfo(url, body, method, contentType, requestID string) {
	if !l.enabled || l.logger == nil {
		return
	}
	l.logger.Printf("info: url=%s, method=%s, contentType=%s, requestId=%s, body=%s",
		url, method, contentType, requestID, body)
}

// logResponseInfo 记录响应信息：状态码、内容、响应头。
func (l *AlipayLogger) logResponseInfo(statusCode int, content []byte, headers http.Header) {
	if !l.enabled || l.logger == nil {
		return
	}
	l.logger.Printf("biz response: code=%d, content=%s, headers=%v", statusCode, string(content), headers)
}

// logBizError 记录业务错误。
func (l *AlipayLogger) logBizError(format string, args ...interface{}) {
	if !l.enabled || l.logger == nil {
		return
	}
	l.logger.Printf("biz error: %s", fmt.Sprintf(format, args...))
}
