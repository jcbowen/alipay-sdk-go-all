package alipay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SdkVersion SDK 标识与版本号（V2 网关兼容参数 alipay_sdk 使用）
const SdkVersion = "alipay-sdk-go-2026-10-18"

// GenericExecuteApi 通用接口执行器。
//
// 对齐 PHP SDK 的 Alipay\OpenAPISDK\Util\GenericExecuteApi：
//   - Execute：调用任意 V3 REST 接口（自动签名、验签、解密）；
//   - PageExecute / SdkExecute：生成 V2 网关（gateway.do）的支付页面参数，
//     兼容 App 支付、手机网站支付、电脑网站支付等页面类接口。
//
// 使用示例：
//
//	executor, err := alipay.NewGenericExecuteApi(configUtil)
//	resp, apiErr := executor.Execute("/v3/alipay/trade/query", "GET",
//	    &alipay.OpenApiGenericRequest{QueryParams: map[string][]string{"out_trade_no": {"123"}}})
type GenericExecuteApi struct {
	configUtil *AlipayConfigUtil
	client     *http.Client
	baseUrl    string // pageExecute 使用的 V2 网关基础地址
	loadTest   bool
}

// NewGenericExecuteApi 创建通用执行器。
//
// 参数:
//   - configUtil: 配置工具，不能为 nil
//
// 返回值:
//   - *GenericExecuteApi: 执行器实例
//   - error: configUtil 为空时返回错误
func NewGenericExecuteApi(configUtil *AlipayConfigUtil) (*GenericExecuteApi, error) {
	if configUtil == nil {
		return nil, fmt.Errorf("AlipayConfigUtil 不能为空")
	}
	return &GenericExecuteApi{
		configUtil: configUtil,
		client:     http.DefaultClient,
	}, nil
}

// SetHttpClient 注入自定义 HTTP 客户端（如配置超时、代理）。
//
// 参数:
//   - client: *http.Client 实例
func (g *GenericExecuteApi) SetHttpClient(client *http.Client) {
	if client != nil {
		g.client = client
	}
}

// SetBaseUrl 设置 V2 网关基础地址（pageExecute 使用），空则回退 serverUrl + /gateway.do。
func (g *GenericExecuteApi) SetBaseUrl(url string) {
	g.baseUrl = strings.TrimSpace(url)
}

// SetLoadTest 设置压测模式（app_id 追加 _TEST_1A 后缀，仅用于联调环境）。
func (g *GenericExecuteApi) SetLoadTest(enabled bool) {
	g.loadTest = enabled
}

// GetAlipayConfigUtil 返回内部配置工具。
func (g *GenericExecuteApi) GetAlipayConfigUtil() *AlipayConfigUtil {
	return g.configUtil
}

// Execute 调用任意 V3 接口并返回通用对象。
//
// 参数:
//   - resourcePath: 接口路径（如 /v3/alipay/trade/pay，可含 {name} 路径占位符）
//   - method: HTTP 方法（GET/POST/PUT/DELETE）
//   - req: 请求参数集合，可为 nil
//
// 返回值:
//   - map[string]interface{}: 响应 JSON 对象
//   - *ApiException: 验签失败、非 2xx 响应等异常
func (g *GenericExecuteApi) Execute(resourcePath, method string, req *OpenApiGenericRequest) (map[string]interface{}, *ApiException) {
	body, _, _, apiErr := g.ExecuteRaw(resourcePath, method, req)
	if apiErr != nil {
		return nil, apiErr
	}
	var result map[string]interface{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, NewApiException(0, "响应 JSON 解析失败: "+err.Error(), nil, string(body))
		}
	}
	return result, nil
}

// ExecuteWithResult 调用任意 V3 接口并将响应反序列化到 result。
//
// 参数:
//   - resourcePath: 接口路径
//   - method: HTTP 方法
//   - req: 请求参数集合，可为 nil
//   - result: 响应反序列化目标（指针），可为 nil（忽略响应体）
//
// 返回值:
//   - *ApiException: 异常，nil 表示成功
func (g *GenericExecuteApi) ExecuteWithResult(resourcePath, method string, req *OpenApiGenericRequest, result interface{}) *ApiException {
	body, _, _, apiErr := g.ExecuteRaw(resourcePath, method, req)
	if apiErr != nil {
		return apiErr
	}
	if result != nil && len(body) > 0 {
		if err := json.Unmarshal(body, result); err != nil {
			return NewApiException(0, "响应 JSON 解析失败: "+err.Error(), nil, string(body))
		}
	}
	return nil
}

// ExecuteRaw 执行请求并返回原始响应。
//
// 内部流程：构造请求（路径/查询/头/体/multipart）→ V3 签名 → 发送 →
// 响应验签 → AES 解密。
//
// 参数:
//   - resourcePath: 接口路径
//   - method: HTTP 方法
//   - req: 请求参数集合，可为 nil
//
// 返回值:
//   - []byte: 解密后的响应体
//   - http.Header: 响应头
//   - int: HTTP 状态码
//   - *ApiException: 异常，nil 表示成功
func (g *GenericExecuteApi) ExecuteRaw(resourcePath, method string, req *OpenApiGenericRequest) ([]byte, http.Header, int, *ApiException) {
	if req == nil {
		req = &OpenApiGenericRequest{}
	}

	isEncrypt, err := g.configUtil.IsEncrypt()
	if err != nil {
		return nil, nil, 0, NewApiException(0, err.Error(), nil, "")
	}

	httpRequest, _, apiErr := g.buildRequest(resourcePath, method, req, isEncrypt)
	if apiErr != nil {
		return nil, nil, 0, apiErr
	}

	resp, err := g.client.Do(httpRequest)
	if err != nil {
		defaultLogger.logBizError("code:0, message:%s", err.Error())
		return nil, nil, 0, NewApiException(0, err.Error(), nil, "")
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, resp.StatusCode, NewApiException(resp.StatusCode, "读取响应失败: "+err.Error(), resp.Header, "")
	}

	// 非 2xx：sign 存在才验签（对齐 PHP isCheckSign=true），随后抛出异常
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if vErr := g.configUtil.VerifyResponse(respBody, resp.Header, true); vErr != nil {
			return nil, resp.Header, resp.StatusCode, toApiException(vErr, resp.Header, string(respBody))
		}
		defaultLogger.logBizError("code:%d, message:%s", resp.StatusCode, string(respBody))
		apiEx := NewApiException(resp.StatusCode,
			fmt.Sprintf("[%d] Error connecting to the API (%s)", resp.StatusCode, httpRequest.URL.String()),
			resp.Header, string(respBody))
		attachErrorObject(g.configUtil, apiEx)
		return nil, resp.Header, resp.StatusCode, apiEx
	}

	// 2xx：必须验签，然后解密（对齐 PHP isCheckSign=false）
	if vErr := g.configUtil.VerifyResponse(respBody, resp.Header, false); vErr != nil {
		return nil, resp.Header, resp.StatusCode, toApiException(vErr, resp.Header, string(respBody))
	}
	content := string(respBody)
	if decrypted, dErr := g.configUtil.Decrypt(content); dErr != nil {
		return nil, resp.Header, resp.StatusCode, NewApiException(0, dErr.Error(), resp.Header, content)
	} else {
		content = decrypted
	}
	defaultLogger.logResponseInfo(resp.StatusCode, []byte(content), resp.Header)

	return []byte(content), resp.Header, resp.StatusCode, nil
}

// IsBizSuccess 判定 V3 响应体业务码是否表示成功。
//
// SDK 对齐 PHP 行为：HTTP 2xx 时不解析响应体 code，调用方需自行判定
// （尤其退款等资金写操作，网关异常场景可能以 HTTP 200 返回非 10000 的 code）。
//
// 参数:
//   - code: 响应体中的 code 字段（如 "10000"）
//
// 返回值:
//   - bool: true 表示业务成功（code == "10000"）
//
// 使用示例:
//
//	if !alipay.IsBizSuccess(fmt.Sprint(result["code"])) { /* 业务失败处理 */ }
func IsBizSuccess(code string) bool {
	return code == "10000"
}

// buildRequest 构造已签名请求。
//
// 参数:
//   - resourcePath: 接口路径
//   - method: HTTP 方法
//   - req: 请求参数集合
//   - isEncrypt: 是否启用敏感信息加密
//
// 返回值:
//   - *http.Request: 已签名请求
//   - string: 参与签名的请求体内容（未加密前的 JSON）
//   - *ApiException: 构造异常
func (g *GenericExecuteApi) buildRequest(resourcePath, method string, req *OpenApiGenericRequest, isEncrypt bool) (*http.Request, string, *ApiException) {
	bodyParams := req.BodyParams
	if bodyParams == nil {
		bodyParams = req.BizParams
	}

	// 路径参数替换
	for k, v := range req.PathParams {
		resourcePath = strings.ReplaceAll(resourcePath, "{"+k+"}", url.PathEscape(v))
	}

	// 请求头
	headerParams := http.Header{}
	for k, v := range req.HeaderParams {
		headerParams.Set(k, v)
	}
	if req.AppAuthToken != "" {
		headerParams.Set("alipay-app-auth-token", req.AppAuthToken)
	}
	headerParams.Set("Accept", "application/json")

	var signContent string
	var httpBody io.Reader
	var contentType string

	if len(req.FileParams) > 0 {
		// multipart 文件上传
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		if bodyParams != nil {
			jsonStr, mErr := marshalJSONUnescaped(bodyParams)
			if mErr != nil {
				return nil, "", NewApiException(0, "请求体序列化失败: "+mErr.Error(), nil, "")
			}
			dataContent := jsonStr
			if isEncrypt {
				encrypted, eErr := g.configUtil.Encrypt(jsonStr)
				if eErr != nil {
					return nil, "", NewApiException(0, eErr.Error(), nil, "")
				}
				dataContent = encrypted
			}
			signContent = jsonStr
			if err := writer.WriteField("data", dataContent); err != nil {
				return nil, "", NewApiException(0, "构造 multipart 失败: "+err.Error(), nil, "")
			}
		}

		// 保证字段顺序稳定
		fieldNames := make([]string, 0, len(req.FileParams))
		for name := range req.FileParams {
			fieldNames = append(fieldNames, name)
		}
		sort.Strings(fieldNames)

		for _, name := range fieldNames {
			for _, f := range req.FileParams[name] {
				content := f.Content
				fileName := f.FileName
				if f.FilePath != "" {
					data, rErr := os.ReadFile(f.FilePath)
					if rErr != nil {
						return nil, "", NewApiException(0, "读取上传文件失败: "+rErr.Error(), nil, "")
					}
					content = data
					if fileName == "" {
						fileName = filepath.Base(f.FilePath)
					}
				}
				part, pErr := writer.CreateFormFile(name, fileName)
				if pErr != nil {
					return nil, "", NewApiException(0, "构造 multipart 文件字段失败: "+pErr.Error(), nil, "")
				}
				if _, wErr := part.Write(content); wErr != nil {
					return nil, "", NewApiException(0, "写入 multipart 文件内容失败: "+wErr.Error(), nil, "")
				}
			}
		}
		if err := writer.Close(); err != nil {
			return nil, "", NewApiException(0, "关闭 multipart 失败: "+err.Error(), nil, "")
		}
		httpBody = body
		contentType = writer.FormDataContentType()
	} else if bodyParams != nil {
		// JSON 请求体
		jsonStr, mErr := marshalJSONUnescaped(bodyParams)
		if mErr != nil {
			return nil, "", NewApiException(0, "请求体序列化失败: "+mErr.Error(), nil, "")
		}
		signContent = jsonStr
		if isEncrypt {
			encrypted, eErr := g.configUtil.Encrypt(jsonStr)
			if eErr != nil {
				return nil, "", NewApiException(0, eErr.Error(), nil, "")
			}
			httpBody = strings.NewReader(encrypted)
			contentType = "text/plain"
			headerParams.Set("alipay-encrypt-type", g.configUtil.GetEncryptType())
		} else {
			httpBody = strings.NewReader(jsonStr)
			contentType = "application/json"
		}
	}

	// 默认头
	headerParams.Set("User-Agent", SdkVersion)
	headerParams.Set("alipay-sdk-version", SdkVersion)
	if contentType != "" {
		headerParams.Set("Content-Type", contentType)
	}
	if headerParams.Get("alipay-request-id") == "" {
		headerParams.Set("alipay-request-id", CreateUUID())
	}

	// 查询串与签名（签名 URI 不含 host，对齐 PHP）
	query := buildQuery(req.QueryParams)
	signUrl := resourcePath
	if query != "" {
		signUrl = resourcePath + "?" + query
	}

	if err := g.configUtil.Sign(strings.ToUpper(method), signUrl, signContent, headerParams); err != nil {
		return nil, "", NewApiException(0, err.Error(), nil, "")
	}

	request, err := http.NewRequest(strings.ToUpper(method), g.configUtil.GetServerUrl()+signUrl, httpBody)
	if err != nil {
		return nil, "", NewApiException(0, "构造 HTTP 请求失败: "+err.Error(), nil, "")
	}
	request.Header = headerParams
	return request, signContent, nil
}

// PageExecute 生成 V2 网关页面类接口的提交内容。
//
// httpMethod 为 GET 时返回带签名的完整跳转 URL（如手机网站支付可 GET 展示）；
// 为 POST 时返回自动提交的表单 HTML（如电脑网站支付）。
//
// 参数:
//   - method: V2 接口方法名（如 alipay.trade.wap.pay）
//   - httpMethod: GET 或 POST
//   - bizParams: 业务参数集合（键为接口参数名；biz_content 键的值可为任意对象）
//   - authToken: 用户授权凭证（auth_token 参数），可为空
//   - appAuthToken: 服务商授权凭证（app_auth_token 参数），可为空
//   - cp: 额外参数，可为 nil
//
// 返回值:
//   - string: URL 或表单 HTML
//   - error: 签名等失败时返回错误
func (g *GenericExecuteApi) PageExecute(method, httpMethod string, bizParams map[string]interface{},
	authToken, appAuthToken string, cp *CustomizedParams) (string, error) {

	handleParams, err := g.handleParams(method, bizParams, authToken, appAuthToken, cp)
	if err != nil {
		return "", err
	}

	baseUrl := g.baseUrl
	if baseUrl == "" {
		baseUrl = g.configUtil.GetServerUrl() + V2GatewayPath
	}

	if strings.EqualFold(httpMethod, "GET") {
		return baseUrl + "?" + buildQueryStr(handleParams), nil
	}
	return buildRequestForm(handleParams, baseUrl), nil
}

// SdkExecute 生成 V2 网关 SDK 类接口的参数串（如 App 支付传给客户端的 order info）。
//
// 参数与返回值同 PageExecute；返回按键名升序拼装的 "k1=v1&k2=v2" 字符串。
func (g *GenericExecuteApi) SdkExecute(method string, bizParams map[string]interface{},
	authToken, appAuthToken string, cp *CustomizedParams) (string, error) {

	handleParams, err := g.handleParams(method, bizParams, authToken, appAuthToken, cp)
	if err != nil {
		return "", err
	}
	return buildQueryStr(handleParams), nil
}

// handleParams 组装 V2 网关请求参数（系统参数 + 业务参数 + 签名），对齐 PHP handleParams。
func (g *GenericExecuteApi) handleParams(method string, bizParams map[string]interface{},
	authToken, appAuthToken string, cp *CustomizedParams) (map[string]string, error) {

	appParams := make(map[string]string)
	systemParams := make(map[string]string)

	if cp != nil && strings.TrimSpace(cp.BodyContent) != "" {
		appParams["biz_content"] = cp.BodyContent
	} else if bizContent, ok := bizParams["biz_content"]; ok {
		jsonStr, err := marshalJSONUnescaped(bizContent)
		if err != nil {
			return nil, err
		}
		appParams["biz_content"] = jsonStr
	}
	for k, v := range bizParams {
		if k == "biz_content" {
			continue
		}
		if s, ok := v.(string); ok {
			appParams[k] = s
		} else {
			jsonStr, err := marshalJSONUnescaped(v)
			if err != nil {
				return nil, err
			}
			appParams[k] = jsonStr
		}
	}

	if cp != nil {
		if cp.AppAuthToken != "" {
			appParams["app_auth_token"] = cp.AppAuthToken
		}
		for k, v := range cp.QueryParams {
			systemParams[k] = v
		}
	}
	if appAuthToken != "" {
		appParams["app_auth_token"] = appAuthToken
	}
	if authToken != "" {
		systemParams["auth_token"] = authToken
	}

	// 系统参数
	systemParams["method"] = method
	systemParams["version"] = "1.0"
	systemParams["alipay_sdk"] = SdkVersion
	systemParams["app_id"] = g.configUtil.GetAppId()
	systemParams["format"] = "json"
	systemParams["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	systemParams["charset"] = "UTF-8"
	systemParams["sign_type"] = SignTypeRSA2
	// 证书序列号仅证书模式有值；公钥模式下不注入，避免页面 URL/表单出现空参数
	if appCertSN := g.configUtil.GetAppCertSN(); appCertSN != "" {
		systemParams["app_cert_sn"] = appCertSN
	}
	if rootCertSN := g.configUtil.GetRootCertSN(); rootCertSN != "" {
		systemParams["alipay_root_cert_sn"] = rootCertSN
	}

	if isEncrypt, err := g.configUtil.IsEncrypt(); err != nil {
		return nil, err
	} else if isEncrypt {
		systemParams["encrypt_type"] = g.configUtil.GetEncryptType()
		bizContent := appParams["biz_content"]
		encrypted, err := g.configUtil.Encrypt(bizContent)
		if err != nil {
			return nil, err
		}
		appParams["biz_content"] = encrypted
	}

	// 合并：appParams 优先（对齐 PHP 数组 + 运算符，同键时左侧 appParams 覆盖）
	totalParams := make(map[string]string, len(appParams)+len(systemParams))
	for k, v := range systemParams {
		totalParams[k] = v
	}
	for k, v := range appParams {
		totalParams[k] = v
	}

	if g.configUtil.IsNeedSign() {
		sign, err := g.configUtil.GenerateSign(GetSignContent(totalParams))
		if err != nil {
			return nil, err
		}
		totalParams["sign"] = sign
	}
	// 对齐 PHP：loadTest 在签名之后替换 app_id（签名内容使用原始 app_id）
	if g.loadTest {
		totalParams["app_id"] = g.configUtil.GetAppId() + "_TEST_1A"
	}
	return totalParams, nil
}

// marshalJSONUnescaped 序列化为不转义 HTML 与 Unicode 的 JSON 文本（对齐 JSON_UNESCAPED_UNICODE）。
func marshalJSONUnescaped(v interface{}) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

// buildQuery 构造查询串（键升序、RFC1738 编码，对齐 http_build_query）。
func buildQuery(queryParams map[string][]string) string {
	if len(queryParams) == 0 {
		return ""
	}
	values := url.Values{}
	for k, vs := range queryParams {
		for _, v := range vs {
			values.Add(k, v)
		}
	}
	return values.Encode()
}

// buildQueryStr 构造字符串参数查询串。
func buildQueryStr(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteString("&")
		}
		sb.WriteString(url.QueryEscape(k) + "=" + url.QueryEscape(params[k]))
	}
	return sb.String()
}

// buildRequestForm 构造自动提交的表单 HTML（对齐 PHP buildRequestForm）。
func buildRequestForm(params map[string]string, actionUrl string) string {
	var sb strings.Builder
	sb.WriteString("<form id='alipaysubmit' name='alipaysubmit' action='" + actionUrl + "?charset=UTF-8' method='POST'>")

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := params[k]
		if strings.TrimSpace(val) == "" {
			continue // 对齐 PHP：空值不生成表单项
		}
		val = strings.ReplaceAll(val, "'", "&apos;")
		sb.WriteString("<input type='hidden' name='" + k + "' value='" + val + "'/>")
	}
	sb.WriteString("<input type='submit' value='ok' style='display:none;'></form>")
	sb.WriteString("<script>document.forms['alipaysubmit'].submit();</script>")
	return sb.String()
}

// toApiException 将内部错误转为 ApiException
func toApiException(err error, headers http.Header, body string) *ApiException {
	if ae, ok := err.(*ApiException); ok {
		return ae
	}
	return NewApiException(0, err.Error(), headers, body)
}

// attachErrorObject 尝试将错误响应体解析为通用错误对象
func attachErrorObject(u *AlipayConfigUtil, apiEx *ApiException) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(apiEx.ResponseBody), &obj); err == nil {
		apiEx.setResponseObject(obj)
	}
}
