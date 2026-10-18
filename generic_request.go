package alipay

// OpenApiGenericRequest 通用接口请求参数集合。
//
// 用于 GenericExecuteApi.Execute 调用任意 V3 接口，字段均可选。
//
// 使用示例：
//
//	req := &alipay.OpenApiGenericRequest{
//	    QueryParams: map[string][]string{"out_trade_no": {"202401011234"}},
//	}
//	result, err := executor.Execute("/v3/alipay/trade/query", "GET", req)
type OpenApiGenericRequest struct {
	// PathParams 路径参数，替换 URI 中 {name} 占位符
	PathParams map[string]string

	// QueryParams 查询参数（支持同名多值）
	QueryParams map[string][]string

	// HeaderParams 额外请求头
	HeaderParams map[string]string

	// BodyParams 请求体对象（struct / map），序列化为 JSON
	BodyParams interface{}

	// FileParams 文件上传参数：字段名 → 文件列表，存在时走 multipart
	FileParams map[string][]*UploadFile

	// AppAuthToken 系统服务商代商家调用时的授权凭证（写入 alipay-app-auth-token 头）
	AppAuthToken string

	// BizParams 业务参数（BodyParams 为空时作为请求体使用，兼容 PHP 版语义）
	BizParams interface{}
}

// AddQueryParam 追加单个查询参数（值仅在非空时写入）。
//
// 参数:
//   - key: 查询参数名
//   - value: 参数值（空串忽略）
func (r *OpenApiGenericRequest) AddQueryParam(key, value string) {
	if r.QueryParams == nil {
		r.QueryParams = make(map[string][]string)
	}
	r.QueryParams[key] = append(r.QueryParams[key], value)
}

// ApplyCustomizedParams 将 CustomizedParams 应用到请求（包内生成代码使用）。
//
// 参数:
//   - cp: 页面类/自定义参数，nil 忽略
func (r *OpenApiGenericRequest) ApplyCustomizedParams(cp *CustomizedParams) {
	if cp == nil {
		return
	}
	if cp.AppAuthToken != "" {
		r.AppAuthToken = cp.AppAuthToken
	}
	for k, v := range cp.QueryParams {
		r.AddQueryParam(k, v)
	}
}

// UploadFile 单个待上传文件。
type UploadFile struct {
	// FileName 上传后使用的文件名，空则取 FilePath 的基名
	FileName string

	// FilePath 本地文件路径（与 Content 二选一，优先 FilePath）
	FilePath string

	// Content 文件内容字节（FilePath 为空时使用）
	Content []byte
}

// CustomizedParams 页面类接口（pageExecute/sdkExecute）的额外参数。
//
// 对齐 PHP SDK 的 Alipay\OpenAPISDK\Util\Model\CustomizedParams。
type CustomizedParams struct {
	// AppAuthToken 系统服务商授权凭证（写入 app_auth_token 参数）
	AppAuthToken string

	// QueryParams 额外系统级参数（并入签名参数）
	QueryParams map[string]string

	// BodyContent 自定义 biz_content 字符串（优先于 bizParams 序列化结果）
	BodyContent string
}
