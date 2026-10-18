package alipay

import (
	"fmt"
	"net/http"
)

// ApiException SDK 统一异常，携带 HTTP 状态码、响应头与响应体。
//
// 对齐 PHP SDK 的 Alipay\OpenAPISDK\ApiException：
// 非法参数、签名失败、验签失败、非 2xx 响应等场景均抛出（返回）本类型。
//
// 使用示例：
//
//	result, err := api.Pay(model)
//	if err != nil {
//	    var ae *alipay.ApiException
//	    if errors.As(err, &ae) {
//	        fmt.Println(ae.Code, ae.ResponseBody)
//	    }
//	}
type ApiException struct {
	// Code HTTP 状态码或 SDK 内部错误码
	Code int

	// Message 错误描述
	Message string

	// ResponseHeaders 响应头（请求已到达服务端时存在）
	ResponseHeaders http.Header

	// ResponseBody 响应体（请求已到达服务端时存在）
	ResponseBody string

	// responseObject 服务端错误响应反序列化结果（如 AlipayDefaultResponse）
	responseObject interface{}
}

// NewApiException 创建 ApiException。
//
// 参数:
//   - code: HTTP 状态码或内部错误码
//   - message: 错误描述
//   - headers: 响应头，可为 nil
//   - body: 响应体，可为空串
//
// 返回值:
//   - *ApiException: 异常对象
func NewApiException(code int, message string, headers http.Header, body string) *ApiException {
	return &ApiException{
		Code:            code,
		Message:         message,
		ResponseHeaders: headers,
		ResponseBody:    body,
	}
}

// Error 实现 error 接口。
func (e *ApiException) Error() string {
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// ResponseObject 返回服务端错误响应的反序列化结果（如有）。
func (e *ApiException) ResponseObject() interface{} {
	return e.responseObject
}

// setResponseObject 设置反序列化结果（包内使用）。
func (e *ApiException) setResponseObject(obj interface{}) {
	e.responseObject = obj
}
