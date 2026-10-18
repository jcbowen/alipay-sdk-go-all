// Package main 是支付宝 V3 SDK 的 Go 代码生成器。
//
// 从官方 alipay-sdk-php-all 仓库 v3/api/oasSchema.json（OpenAPI 3.0 规范）生成：
//   - model/ 包：全部 2722 个 schema 对应的 struct
//   - api/ 包：全部 740 个 operation 对应的 API 方法（按 tag 分组）
//   - docs/endpoints.md：全量端点表
//
// 用法：
//
//	go run ./tools/generator -schema <oasSchema.json 路径> -out <项目根目录>
//
// 生成的代码头部均带有 DO NOT EDIT 标记，修改请调整本生成器后重新运行。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// oasSchema OpenAPI 规范的最小解析模型
type oasSchema struct {
	Paths      map[string]map[string]oasOperation `json:"paths"`
	Components struct {
		Schemas    map[string]oasSchemaDef          `json:"schemas"`
		Parameters map[string]oasParameterOrRef     `json:"parameters"`
	} `json:"components"`
}

// oasSchemaDef 单个 schema 定义（object + properties）
type oasSchemaDef struct {
	Type        string                       `json:"type"`
	Description string                       `json:"description"`
	Properties  map[string]map[string]any    `json:"properties"`
	Required    []string                     `json:"required"`
	AnyOf       []map[string]any             `json:"anyOf"`
}

// oasOperation 单个 operation
type oasOperation struct {
	Tags        []string            `json:"tags"`
	Summary     string              `json:"summary"`
	Description string              `json:"description"`
	OperationID string              `json:"operationId"`
	Parameters  []oasParameterOrRef `json:"parameters"`
	RequestBody *oasRequestBody     `json:"requestBody"`
	Responses   map[string]oasResponse `json:"responses"`
}

// oasParameterOrRef 参数或参数引用
type oasParameterOrRef struct {
	Ref         string         `json:"$ref"`
	Name        string         `json:"name"`
	In          string         `json:"in"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"schema"`
}

// oasRequestBody 请求体
type oasRequestBody struct {
	Content map[string]struct {
		Schema map[string]any `json:"schema"`
	} `json:"content"`
}

// oasResponse 响应
type oasResponse struct {
	Description string `json:"description"`
	Content     map[string]struct {
		Schema map[string]any `json:"schema"`
	} `json:"content"`
}

var (
	httpMethods = map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true}
)

func main() {
	var schemaPath, outDir string
	flag.StringVar(&schemaPath, "schema", "", "oasSchema.json 路径")
	flag.StringVar(&outDir, "out", ".", "输出目录（项目根目录）")
	flag.Parse()

	if schemaPath == "" {
		fmt.Fprintln(os.Stderr, "缺少 -schema 参数")
		os.Exit(1)
	}

	data, err := os.ReadFile(schemaPath)
	if err != nil {
		fatal("读取 schema 失败: %v", err)
	}
	var schema oasSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		fatal("解析 schema 失败: %v", err)
	}

	genTime := time.Now().Format("2006-01-02 15:04:05")
	ctx := &genContext{
		schema:  &schema,
		outDir:  outDir,
		genTime: genTime,
	}

	// 1. 收集模型与操作
	ctx.collectModels()
	if err := ctx.collectOperations(); err != nil {
		fatal("收集 operation 失败: %v", err)
	}

	// 2. 生成代码
	if err := ctx.generateModels(); err != nil {
		fatal("生成 model 失败: %v", err)
	}
	if err := ctx.generateAPIs(); err != nil {
		fatal("生成 api 失败: %v", err)
	}
	if err := ctx.generateEndpointDoc(); err != nil {
		fatal("生成端点文档失败: %v", err)
	}

	fmt.Printf("生成完成：%d 个 Model struct，%d 个 API 方法，输出目录 %s\n",
		len(ctx.models), len(ctx.operations), outDir)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "错误: "+format+"\n", args...)
	os.Exit(1)
}

// genContext 生成上下文
type genContext struct {
	schema     *oasSchema
	outDir     string
	genTime    string
	models     []modelInfo            // 顶层 schema 列表
	modelNames map[string]bool        // schema 名集合（校验 $ref）
	operations []operationInfo        // 全量操作
	tags       []string               // 有序 tag 列表
	tagOps     map[string][]int       // tag → operations 下标
}

// modelInfo 一个待生成 struct
type modelInfo struct {
	Name        string
	Description string
	Fields      []fieldInfo
}

// fieldInfo struct 字段
type fieldInfo struct {
	GoName    string
	JSONName  string
	GoType    string
	Comment   string
	Required  bool
}

// operationInfo 一个 API 操作
type operationInfo struct {
	Tag          string
	ClassName    string // API 类名（AlipayTradeApi）
	MethodName   string // 方法名（Pay）
	HTTPMethod   string // POST/GET/PUT/DELETE
	Path         string
	Summary      string
	RequestModel string         // 请求 Model 名（JSON body）
	FileFields   []fileField    // multipart 文件字段
	QueryParams  []queryParam   // 查询参数
	ResponseModel string        // 响应 Model 名
}

// fileField multipart 文件字段
type fileField struct {
	Name    string // 字段名
	GoName  string // 参数名（camelCase）
}

// queryParam 查询参数
type queryParam struct {
	Name        string
	GoName      string
	GoType      string
	Description string
}

// collectModels 解析全部顶层 schema 为 modelInfo
func (g *genContext) collectModels() {
	g.modelNames = make(map[string]bool)
	for name := range g.schema.Components.Schemas {
		g.modelNames[name] = true
	}

	for name, def := range g.schema.Components.Schemas {
		mi := modelInfo{
			Name:        name,
			Description: oneLine(def.Description),
		}
		// 字段名 → Go 名冲突检测
		used := make(map[string]int)
		for jsonName, prop := range def.Properties {
			goName := pascal(jsonName)
			if n, exists := used[goName]; exists {
				used[goName] = n + 1
				goName = fmt.Sprintf("%s%d", goName, n)
			} else {
				used[goName] = 1
			}
			required := false
			for _, r := range def.Required {
				if r == jsonName {
					required = true
					break
				}
			}
			goType, err := goTypeOf(prop, g.modelNames)
			if err != nil {
				fatal("schema %s 字段 %s: %v", name, jsonName, err)
			}
			mi.Fields = append(mi.Fields, fieldInfo{
				GoName:   goName,
				JSONName: jsonName,
				GoType:   goType,
				Comment:  oneLine(prop["description"]),
				Required: required,
			})
		}
		g.models = append(g.models, mi)
	}
	// 稳定排序
	sortModels(g.models)
}

// collectOperations 解析全部 path → operation
func (g *genContext) collectOperations() error {
	for path, ops := range g.schema.Paths {
		for method, op := range ops {
			if !httpMethods[method] {
				continue
			}
			if op.OperationID == "" {
				continue
			}
			tag := op.Tags[0]
			rest := strings.TrimPrefix(op.OperationID, tag+".")
			if rest == op.OperationID || strings.Contains(rest, ".") {
				return fmt.Errorf("operationId %s 与 tag %s 不匹配", op.OperationID, tag)
			}

			info := operationInfo{
				Tag:        tag,
				ClassName:  pascal(strings.Split(tag, ".")...) + "Api",
				MethodName: upperFirst(rest),
				HTTPMethod: strings.ToUpper(method),
				Path:       path,
				Summary:    oneLine(op.Summary),
			}

			// 查询参数（含 $ref 引用）
			for _, p := range op.Parameters {
				param := p
				if param.Ref != "" {
					refName := refLastName(param.Ref)
					resolved, ok := g.schema.Components.Parameters[refName]
					if !ok {
						return fmt.Errorf("未找到参数引用 %s（%s）", param.Ref, op.OperationID)
					}
					param = resolved
				}
				if param.In != "query" {
					continue
				}
				goType := "*string"
				if param.Schema != nil {
					t, err := goTypeOf(param.Schema, g.modelNames)
					if err != nil {
						return fmt.Errorf("参数 %s: %w", param.Name, err)
					}
					goType = t
				}
				info.QueryParams = append(info.QueryParams, queryParam{
					Name:        param.Name,
					GoName:      lowerFirstCamel(param.Name),
					GoType:      goType,
					Description: oneLine(param.Description),
				})
			}
			// 对齐 PHP：查询参数按名称排序
			sortQueryParams(info.QueryParams)

			// 请求体
			if op.RequestBody != nil {
				if jsonContent, ok := op.RequestBody.Content["application/json"]; ok {
					if ref, ok := jsonContent.Schema["$ref"].(string); ok {
						info.RequestModel = refLastName(ref)
					}
				}
				if formData, ok := op.RequestBody.Content["multipart/form-data"]; ok {
					if props, ok := formData.Schema["properties"].(map[string]any); ok {
						for name, p := range props {
							pm := p.(map[string]any)
							if pm["type"] == "string" && pm["format"] == "binary" {
								info.FileFields = append(info.FileFields, fileField{
									Name:   name,
									GoName: lowerFirstCamel(name),
								})
							}
						}
					}
				}
			}

			// 响应体（200 → ResponseModel）
			if resp, ok := op.Responses["200"]; ok {
				for _, content := range resp.Content {
					if ref, ok := content.Schema["$ref"].(string); ok {
						info.ResponseModel = refLastName(ref)
						break
					}
				}
			}

			g.operations = append(g.operations, info)
		}
	}

	// 按 tag 分组并保持稳定顺序
	g.tagOps = make(map[string][]int)
	for i, op := range g.operations {
		if _, exists := g.tagOps[op.Tag]; !exists {
			g.tags = append(g.tags, op.Tag)
		}
		g.tagOps[op.Tag] = append(g.tagOps[op.Tag], i)
	}

	// 同类内方法名冲突检测
	for _, tag := range g.tags {
		seen := make(map[string]string)
		for _, idx := range g.tagOps[tag] {
			op := g.operations[idx]
			if prev, dup := seen[op.MethodName]; dup {
				return fmt.Errorf("tag %s 存在同名方法 %s（%s 与 %s）", tag, op.MethodName, prev, op.Path)
			}
			seen[op.MethodName] = op.Path
		}
	}
	return nil
}

// goTypeOf 将 OpenAPI 属性定义映射为 Go 类型
//
// 支持的形态（经统计 schema 全覆盖）：
//   - $ref → *Target
//   - string → *string；integer → *int64；boolean → *bool；number → *float64
//   - array + items $ref → []*Target；array + items 基础类型 → []T
func goTypeOf(prop map[string]any, known map[string]bool) (string, error) {
	if ref, ok := prop["$ref"].(string); ok {
		name := refLastName(ref)
		if !known[name] {
			return "", fmt.Errorf("未知引用 %s", ref)
		}
		return "*" + name, nil
	}
	switch prop["type"] {
	case "string":
		return "*string", nil
	case "integer":
		return "*int64", nil
	case "boolean":
		return "*bool", nil
	case "number":
		return "*float64", nil
	case "array":
		items, _ := prop["items"].(map[string]any)
		if items == nil {
			return "[]any", nil
		}
		if ref, ok := items["$ref"].(string); ok {
			name := refLastName(ref)
			if !known[name] {
				return "", fmt.Errorf("数组未知引用 %s", ref)
			}
			return "[]*" + name, nil
		}
		switch items["type"] {
		case "string":
			return "[]string", nil
		case "integer":
			return "[]int64", nil
		case "boolean":
			return "[]bool", nil
		case "number":
			return "[]float64", nil
		}
		return "[]any", nil
	}
	return "", fmt.Errorf("不支持的属性类型: %v", prop["type"])
}

// refLastName 从 "#/components/schemas/X" 取 X
func refLastName(ref string) string {
	parts := strings.Split(ref, "/")
	return parts[len(parts)-1]
}

// pascal 下划线/点分段转 PascalCase
func pascal(parts ...string) string {
	var sb strings.Builder
	for _, part := range parts {
		for _, seg := range strings.Split(part, "_") {
			sb.WriteString(upperFirst(seg))
		}
	}
	return sb.String()
}

// lowerFirstCamel 标识符转 lowerCamelCase；结果若为 Go 关键字则追加下划线。
//
// 兼容两种输入：snake_case（如 "auth_token" → "authToken"）、
// PascalCase（如 "AlipayTradePayModel" → "alipayTradePayModel"）。
func lowerFirstCamel(s string) string {
	var parts []string
	if strings.Contains(s, "_") {
		parts = strings.Split(s, "_")
		for i := range parts {
			parts[i] = strings.ToLower(parts[i])
		}
	} else {
		parts = splitPascal(s)
		for i := 1; i < len(parts); i++ {
			parts[i] = strings.ToLower(parts[i])
		}
	}

	var sb strings.Builder
	for i, part := range parts {
		if i == 0 {
			sb.WriteString(strings.ToLower(part))
		} else {
			sb.WriteString(upperFirst(part))
		}
	}
	name := sb.String()
	if goKeywords[name] {
		return name + "_"
	}
	return name
}

// goKeywords Go 语言关键字集合（不可作为标识符）
var goKeywords = map[string]bool{
	"break": true, "case": true, "chan": true, "const": true, "continue": true,
	"default": true, "defer": true, "else": true, "fallthrough": true, "for": true,
	"func": true, "go": true, "goto": true, "if": true, "import": true,
	"interface": true, "map": true, "package": true, "range": true, "return": true,
	"select": true, "struct": true, "switch": true, "type": true, "var": true,
}

// upperFirst 首字母大写（保持其余字符）
func upperFirst(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	r[0] = []rune(strings.ToUpper(string(r[0])))[0]
	return string(r)
}

// oneLine 压缩注释为单行
func oneLine(s any) string {
	str, ok := s.(string)
	if !ok || str == "" {
		return ""
	}
	return strings.Join(strings.FieldsFunc(str, func(r rune) bool { return r == '\n' || r == '\r' }), " ")
}

// sortModels 按名称排序
func sortModels(models []modelInfo) {
	for i := 1; i < len(models); i++ {
		for j := i; j > 0 && models[j].Name < models[j-1].Name; j-- {
			models[j], models[j-1] = models[j-1], models[j]
		}
	}
}

// sortQueryParams 按参数名排序（对齐 PHP openapi-generator 行为）
func sortQueryParams(params []queryParam) {
	for i := 1; i < len(params); i++ {
		for j := i; j > 0 && params[j].Name < params[j-1].Name; j-- {
			params[j], params[j-1] = params[j-1], params[j]
		}
	}
}

// ensureDir 确保目录存在
func ensureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

// writeFile 写文件
func writeFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", filepath.Base(path), err)
	}
	return nil
}
