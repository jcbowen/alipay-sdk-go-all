module github.com/jcbowen/alipay-sdk-go-all

go 1.26.0

require github.com/jcbowen/jcbaseGo v0.16.8

require (
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/crypto v0.58.0 // indirect
)

// 本地开发引用；正式发布时移除 replace 并将 jcbaseGo 作为常规 require 依赖
// replace github.com/jcbowen/jcbaseGo => ../jcbaseGo
