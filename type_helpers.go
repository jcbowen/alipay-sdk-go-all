package alipay

// 本文件提供 Model 指针字段的快捷构造函数。
//
// 生成的 Model 字段全部为指针类型（可区分"未设置"与"零值"，
// 保证序列化结果与签名内容一致），配合以下函数可简洁赋值：
//
//	model.Subject = alipay.Str("测试商品")
//	model.TotalAmount = alipay.Str("0.01")
//	model.TimeoutExpress = alipay.Int64(15)

// Str 返回字符串指针。
//
// 参数:
//   - v: 字符串值
//
// 返回值:
//   - *string: 字符串指针
func Str(v string) *string { return &v }

// Bool 返回布尔指针。
//
// 参数:
//   - v: 布尔值
//
// 返回值:
//   - *bool: 布尔指针
func Bool(v bool) *bool { return &v }

// Int64 返回 int64 指针。
//
// 参数:
//   - v: 整数值
//
// 返回值:
//   - *int64: int64 指针
func Int64(v int64) *int64 { return &v }

// Int32 返回 int32 指针。
//
// 参数:
//   - v: 整数值
//
// 返回值:
//   - *int32: int32 指针
func Int32(v int32) *int32 { return &v }

// Float64 返回 float64 指针。
//
// 参数:
//   - v: 浮点值
//
// 返回值:
//   - *float64: float64 指针
func Float64(v float64) *float64 { return &v }

// DerefStr 安全解引用字符串指针，nil 返回空串。
//
// 参数:
//   - p: 字符串指针，可为 nil
//
// 返回值:
//   - string: 解引用结果
func DerefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
