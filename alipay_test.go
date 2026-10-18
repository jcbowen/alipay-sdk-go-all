package alipay

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// genKeyPair 生成测试 RSA 密钥对
func genKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	return key
}

// genSelfSignedCert 生成自签证书，issuer 固定为 C=CN,O=Alipay,CN=Test CA 以便断言反序结果
func genSelfSignedCert(t *testing.T, serial *big.Int) (certPEM string) {
	t.Helper()
	key := genKeyPair(t)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"Alipay"},
			OrganizationalUnit: []string{"Test OU"},
			CommonName:         "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestCertSNIssuerReversed 核心校验：issuer 按反序拼接后取 MD5（对齐 PHP array_reverse）
func TestCertSNIssuerReversed(t *testing.T) {
	certPEM := genSelfSignedCert(t, big.NewInt(123456789))

	cert, err := ParseCertificate([]byte(certPEM))
	if err != nil {
		t.Fatal(err)
	}

	// 独立按 PHP 规则计算期望值：反序后 "CN=Test CA,OU=Test OU,O=Alipay,C=CN" + serialNumber
	expected := md5Hex("CN=Test CA,OU=Test OU,O=Alipay,C=CN" + cert.SerialNumber.String())

	sn, err := CertSN(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if sn != expected {
		t.Fatalf("certSN 不符：got=%s want=%s", sn, expected)
	}
}

// TestRootCertSNMultiSegment 校验根证书多段 SN 下划线连接与签名算法过滤
func TestRootCertSNMultiSegment(t *testing.T) {
	seg1 := genSelfSignedCert(t, big.NewInt(111))
	seg2 := genSelfSignedCert(t, big.NewInt(222))
	root := seg1 + "\n" + seg2

	sn1, err := CertSN(seg1)
	if err != nil {
		t.Fatal(err)
	}
	sn2, err := CertSN(seg2)
	if err != nil {
		t.Fatal(err)
	}

	got, err := RootCertSN(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != sn1+"_"+sn2 {
		t.Fatalf("rootCertSN 不符：got=%s want=%s_%s", got, sn1, sn2)
	}
}

// TestConfigUtilSignAuthorizationFormat 校验 V3 Authorization 头格式与待签串
func TestConfigUtilSignAuthorizationFormat(t *testing.T) {
	key := genKeyPair(t)
	cfg := &AlipayConfig{
		AppId:      "2021000100000000",
		PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)),
	}
	u, err := NewAlipayConfigUtil(cfg)
	if err != nil {
		t.Fatal(err)
	}

	headers := http.Header{}
	if err := u.Sign("POST", "/v3/alipay/trade/pay", `{"a":1}`, headers); err != nil {
		t.Fatal(err)
	}
	auth := headers.Get("Authorization")
	if !strings.HasPrefix(auth, "ALIPAY-SHA256withRSA app_id=2021000100000000,nonce=") {
		t.Fatalf("Authorization 格式错误: %s", auth)
	}
	if !strings.Contains(auth, ",timestamp=") || !strings.Contains(auth, ",sign=") {
		t.Fatalf("Authorization 缺少字段: %s", auth)
	}
	if strings.Contains(auth, "app_cert_sn") {
		t.Fatalf("公钥模式不应包含 app_cert_sn: %s", auth)
	}

	// 证书模式包含 app_cert_sn
	certPEM := genSelfSignedCert(t, big.NewInt(999))
	cfg2 := &AlipayConfig{
		AppId:           "2021000100000000",
		PrivateKey:      base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)),
		AppCertContent:  certPEM,
		AlipayPublicCertContent: certPEM,
		RootCertContent: certPEM,
	}
	u2, err := NewAlipayConfigUtil(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if u2.GetAppCertSN() == "" || u2.GetRootCertSN() == "" {
		t.Fatal("证书模式 appCertSN/rootCertSN 不应为空")
	}
	headers2 := http.Header{}
	if err := u2.Sign("GET", "/v3/x", "", headers2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(headers2.Get("Authorization"), ",app_cert_sn=") {
		t.Fatal("证书模式 Authorization 应含 app_cert_sn")
	}
}

// TestAESRoundTrip AES 加解密往返 + 已知答案（零 IV）
func TestAESRoundTrip(t *testing.T) {
	// 16 字节 key（base64 后即支付宝 encryptKey 常见形态）
	key := "1234567890abcdef"
	encryptKey := base64.StdEncoding.EncodeToString([]byte(key))

	cfg := &AlipayConfig{AppId: "x", PrivateKey: "", EncryptKey: encryptKey}
	u, err := NewAlipayConfigUtil(cfg)
	if err != nil {
		t.Fatal(err)
	}

	plain := `{"name":"测试商品","amount":"0.01"}`
	cipherText, err := u.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := u.Decrypt(cipherText)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("解密不符: %s", got)
	}

	// 已知答案：手工用标准库验证加密结果正确性（零 IV、PKCS7）
	block, _ := aesNewCipher([]byte(key))
	data := pkcs7Pad([]byte(plain), block.BlockSize())
	iv := make([]byte, block.BlockSize())
	out := make([]byte, len(data))
	aesCBCEncrypt(block, iv, out, data)
	if cipherText != base64.StdEncoding.EncodeToString(out) {
		t.Fatal("AES 加密结果与标准实现不一致")
	}

	// 未配置 encryptKey 时原样返回
	cfgNoKey := &AlipayConfig{AppId: "x"}
	u2, _ := NewAlipayConfigUtil(cfgNoKey)
	same, err := u2.Encrypt(plain)
	if err != nil || same != plain {
		t.Fatal("未配置 encryptKey 应原样返回")
	}
}

// TestExecuteFullFlow httptest 全流程：请求签名→服务端验签→响应签名→客户端验签→JSON 解析
func TestExecuteFullFlow(t *testing.T) {
	serverKey := genKeyPair(t)
	clientKey := genKeyPair(t)

	// 客户端配置（公钥模式，公钥=服务端私钥对应公钥）
	alipayPub, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &AlipayConfig{
		AppId:           "2021000100000000",
		PrivateKey:      base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(clientKey)),
		AlipayPublicKey: base64.StdEncoding.EncodeToString(alipayPub),
	}
	u, err := NewAlipayConfigUtil(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 服务端：验客户端签 → 签响应（待签串 timestamp\nnonce\nbody\n）
	var verified bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// 服务端用客户端公钥验签请求（模拟支付宝侧）
		ok, err := verifyRequestWithServerKey(r, string(body), clientKey)
		if err != nil || !ok {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"code":"401","message":"sign check fail"}`))
			return
		}
		verified = true

		respBody := `{"trade_no":"20240101001","buyer_pay_amount":"0.01"}`
		timestamp, nonce := GetCurrentMilis(), CreateUUID()
		content := timestamp + "\n" + nonce + "\n" + respBody + "\n"
		digest := sha256Digest([]byte(content))
		sig, _ := rsaSignPKCS1(serverKey, digest)
		w.Header().Set("alipay-signature", sig)
		w.Header().Set("alipay-sn", "test-sn")
		w.Header().Set("alipay-timestamp", timestamp)
		w.Header().Set("alipay-nonce", nonce)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(respBody))
	}))
	defer ts.Close()

	u.serverUrl = ts.URL
	executor, err := NewGenericExecuteApi(u)
	if err != nil {
		t.Fatal(err)
	}

	result, apiEx := executor.Execute("/v3/alipay/trade/query", "POST",
		&OpenApiGenericRequest{BodyParams: map[string]string{"out_trade_no": "123"}})
	if apiEx != nil {
		t.Fatalf("请求失败: %v", apiEx)
	}
	if !verified {
		t.Fatal("服务端验签应通过")
	}
	if DerefStr(strPtr(result["trade_no"])) != "20240101001" {
		t.Fatalf("响应解析错误: %v", result)
	}
}

// verifyRequestWithServerKey 模拟支付宝服务端按 V3 规则验签请求
func verifyRequestWithServerKey(r *http.Request, body string, clientKey *rsa.PrivateKey) (bool, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "ALIPAY-SHA256withRSA ") {
		return false, fmt.Errorf("缺少认证串")
	}
	authString := strings.TrimPrefix(auth, "ALIPAY-SHA256withRSA ")
	idx := strings.LastIndex(authString, ",sign=")
	if idx < 0 {
		return false, fmt.Errorf("缺少 sign")
	}
	sign := authString[idx+len(",sign="):]
	content := authString[:idx] + "\n" + r.Method + "\n" + r.URL.RequestURI() + "\n" + body + "\n"
	digest := sha256Digest([]byte(content))
	return rsaVerifyPKCS1(&clientKey.PublicKey, digest, sign)
}

// TestVerifyResponseFail 校验验签失败抛 ApiException
func TestVerifyResponseFail(t *testing.T) {
	serverKey := genKeyPair(t)
	clientKey := genKeyPair(t)
	alipayPub, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	cfg := &AlipayConfig{
		AppId:           "x",
		PrivateKey:      base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(clientKey)),
		AlipayPublicKey: base64.StdEncoding.EncodeToString(alipayPub),
	}
	u, _ := NewAlipayConfigUtil(cfg)

	headers := http.Header{}
	headers.Set("alipay-signature", "invalid-sign")
	headers.Set("alipay-sn", "sn")
	headers.Set("alipay-timestamp", GetCurrentMilis())
	headers.Set("alipay-nonce", "nonce")

	err := u.VerifyResponse([]byte(`{"a":1}`), headers, false)
	if err == nil {
		t.Fatal("非法签名应验签失败")
	}
	ae, ok := err.(*ApiException)
	if !ok || ae.Code != 400 {
		t.Fatalf("应为 ApiException(400): %v", err)
	}
}

// TestV2SdkExecute 校验 V2 网关参数与签名内容
func TestV2SdkExecute(t *testing.T) {
	key := genKeyPair(t)
	cfg := &AlipayConfig{
		AppId:      "2021000100000000",
		PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)),
	}
	u, err := NewAlipayConfigUtil(cfg)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewGenericExecuteApi(u)
	if err != nil {
		t.Fatal(err)
	}

	out, err := executor.SdkExecute("alipay.trade.app.pay", map[string]interface{}{
		"biz_content": map[string]interface{}{"out_trade_no": "123", "total_amount": "0.01", "subject": "测试"},
	}, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "method=alipay.trade.app.pay") {
		t.Fatalf("缺少 method 参数: %s", out)
	}
	if !strings.Contains(out, "sign_type=RSA2") {
		t.Fatalf("缺少 sign_type: %s", out)
	}
	if !strings.Contains(out, "sign=") {
		t.Fatalf("缺少签名: %s", out)
	}
	// biz_content 值为 URL 编码的 JSON
	if !strings.Contains(out, "biz_content=") {
		t.Fatalf("缺少 biz_content: %s", out)
	}
}

// TestV2PageExecuteGet 校验 pageExecute GET 返回完整 URL
func TestV2PageExecuteGet(t *testing.T) {
	key := genKeyPair(t)
	cfg := &AlipayConfig{AppId: "app001", PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key))}
	u, _ := NewAlipayConfigUtil(cfg)
	executor, _ := NewGenericExecuteApi(u)

	out, err := executor.PageExecute("alipay.trade.wap.pay", "GET",
		map[string]interface{}{"biz_content": map[string]interface{}{"out_trade_no": "1"}}, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, DefaultServerUrl+V2GatewayPath+"?") {
		t.Fatalf("URL 前缀错误: %s", out)
	}
}

// TestV2PageExecutePost 校验 pageExecute POST 返回表单 HTML
func TestV2PageExecutePost(t *testing.T) {
	key := genKeyPair(t)
	cfg := &AlipayConfig{AppId: "app001", PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key))}
	u, _ := NewAlipayConfigUtil(cfg)
	executor, _ := NewGenericExecuteApi(u)

	out, err := executor.PageExecute("alipay.trade.page.pay", "POST",
		map[string]interface{}{"biz_content": map[string]interface{}{"out_trade_no": "1"}}, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<form id='alipaysubmit'") {
		t.Fatalf("表单 HTML 格式错误: %s", out)
	}
	if !strings.Contains(out, "document.forms['alipaysubmit'].submit()") {
		t.Fatal("缺少自动提交脚本")
	}
}

// TestGetSignContent 校验签名串：排序、空值与 @ 前缀跳过
func TestGetSignContent(t *testing.T) {
	params := map[string]string{
		"b": "2", "a": "1", "c": "", "d": "@file.txt", "e": " ",
	}
	got := GetSignContent(params)
	if got != "a=1&b=2" {
		t.Fatalf("签名串不符: %s", got)
	}
}

// TestRsaCheckV1V2 校验异步通知验签（自签后验）
func TestRsaCheckV1V2(t *testing.T) {
	key := genKeyPair(t)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	params := map[string]string{
		"gmt_create":  "2024-01-01 00:00:00",
		"trade_no":    "20240101001",
		"out_trade_no": "123",
		"trade_status": "TRADE_SUCCESS",
		"sign_type":   "RSA2",
		"sign":        "",
	}

	// V1：剔除 sign 与 sign_type 后签名
	params["sign"], _ = AloneRsaSign(GetSignContent(copyParamsDelete(params, "sign", "sign_type")),
		base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)), false)
	ok, err := RsaCheckV1(params, pubB64, false)
	if err != nil || !ok {
		t.Fatalf("V1 验签失败: %v %v", ok, err)
	}

	// V2：仅剔除 sign
	params["sign"], _ = AloneRsaSign(GetSignContent(copyParamsDelete(params, "sign")),
		base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)), false)
	ok, err = RsaCheckV2(params, pubB64, false)
	if err != nil || !ok {
		t.Fatalf("V2 验签失败: %v %v", ok, err)
	}

	// 篡改后失败
	params["trade_status"] = "TRADE_CLOSED"
	ok, err = RsaCheckV1(params, pubB64, false)
	if err != nil || ok {
		t.Fatal("篡改后 V1 验签应失败")
	}
}

// TestEncryptRequestFlow 加密请求全流程：加密体 + text/plain + alipay-encrypt-type
func TestEncryptRequestFlow(t *testing.T) {
	serverKey := genKeyPair(t)
	clientKey := genKeyPair(t)
	alipayPub, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	encryptKey := base64.StdEncoding.EncodeToString([]byte("1234567890abcdef"))

	var gotEncType, gotContentType, gotRawBody string
	serverEncryptKey := "1234567890abcdef"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotEncType = r.Header.Get("alipay-encrypt-type")
		gotContentType = r.Header.Get("Content-Type")
		gotRawBody = string(body)

		// 响应体同样加密（加密模式下支付宝返回 AES 密文）
		respBody, _ := encryptAES(`{"ok":true}`, serverEncryptKey)
		timestamp, nonce := GetCurrentMilis(), CreateUUID()
		content := timestamp + "\n" + nonce + "\n" + respBody + "\n"
		sig, _ := rsaSignPKCS1(serverKey, sha256Digest([]byte(content)))
		w.Header().Set("alipay-signature", sig)
		w.Header().Set("alipay-timestamp", timestamp)
		w.Header().Set("alipay-nonce", nonce)
		_, _ = w.Write([]byte(respBody))
	}))
	defer ts.Close()

	cfg := &AlipayConfig{
		AppId:           "x",
		PrivateKey:      base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(clientKey)),
		AlipayPublicKey: base64.StdEncoding.EncodeToString(alipayPub),
		EncryptKey:      encryptKey,
	}
	u, _ := NewAlipayConfigUtil(cfg)
	u.serverUrl = ts.URL
	executor, _ := NewGenericExecuteApi(u)

	var result map[string]interface{}
	if apiEx := executor.ExecuteWithResult("/v3/test", "POST", &OpenApiGenericRequest{
		BodyParams: map[string]string{"a": "1"},
	}, &result); apiEx != nil {
		t.Fatal(apiEx)
	}
	if gotEncType != "AES" {
		t.Fatalf("alipay-encrypt-type 应为 AES: %s", gotEncType)
	}
	if gotContentType != "text/plain" {
		t.Fatalf("加密时 Content-Type 应为 text/plain: %s", gotContentType)
	}
	// 服务端解密校验：请求体应为合法 AES 密文
	plain, err := decryptAES(gotRawBody, "1234567890abcdef")
	if err != nil || !strings.Contains(plain, `"a":"1"`) {
		t.Fatalf("请求体应为可解密密文: %s, err=%v", gotRawBody, err)
	}
}

// TestApiExceptionOnError 校验非 2xx 响应抛 ApiException 并携带响应信息
func TestApiExceptionOnError(t *testing.T) {
	serverKey := genKeyPair(t)
	clientKey := genKeyPair(t)
	alipayPub, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"code":"40004","message":"无权限"}`
		timestamp, nonce := GetCurrentMilis(), CreateUUID()
		content := timestamp + "\n" + nonce + "\n" + body + "\n"
		sig, _ := rsaSignPKCS1(serverKey, sha256Digest([]byte(content)))
		w.Header().Set("alipay-signature", sig)
		w.Header().Set("alipay-timestamp", timestamp)
		w.Header().Set("alipay-nonce", nonce)
		w.WriteHeader(400)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	cfg := &AlipayConfig{
		AppId:           "x",
		PrivateKey:      base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(clientKey)),
		AlipayPublicKey: base64.StdEncoding.EncodeToString(alipayPub),
	}
	u, _ := NewAlipayConfigUtil(cfg)
	u.serverUrl = ts.URL
	executor, _ := NewGenericExecuteApi(u)

	_, apiEx := executor.Execute("/v3/test", "POST", &OpenApiGenericRequest{
		BodyParams: map[string]string{"a": "1"},
	})
	if apiEx == nil {
		t.Fatal("非 2xx 应返回 ApiException")
	}
	if apiEx.Code != 400 {
		t.Fatalf("状态码应为 400: %d", apiEx.Code)
	}
	var errObj map[string]interface{}
	if err := json.Unmarshal([]byte(apiEx.ResponseBody), &errObj); err != nil {
		t.Fatal("响应体应可解析")
	}
	if apiEx.ResponseObject() == nil {
		t.Fatal("ResponseObject 应已填充")
	}
}

// ---- 测试辅助 ----

// aesNewCipher 包装 aes.NewCipher
func aesNewCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// aesCBCEncrypt 包装 cipher.NewCBCEncrypter().CryptBlocks
func aesCBCEncrypt(block cipher.Block, iv, dst, src []byte) {
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
}

// sha256Digest 计算 SHA-256 摘要
func sha256Digest(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// rsaSignPKCS1 用私钥对 SHA-256 摘要签名并返回 base64
func rsaSignPKCS1(key *rsa.PrivateKey, digest []byte) (string, error) {
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// rsaVerifyPKCS1 用公钥对 base64 签名验签
func rsaVerifyPKCS1(key *rsa.PublicKey, digest []byte, signB64 string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(signB64)
	if err != nil {
		return false, err
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sig); err != nil {
		return false, nil
	}
	return true, nil
}

func copyParamsDelete(params map[string]string, deletes ...string) map[string]string {
	copied := make(map[string]string, len(params))
	for k, v := range params {
		copied[k] = v
	}
	for _, d := range deletes {
		delete(copied, d)
	}
	return copied
}

func strPtr(v interface{}) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}
