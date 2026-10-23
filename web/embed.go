// Package web 内嵌前端静态资源，编译后单个二进制即可运行。
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// Static 返回前端静态文件系统（根目录为 static/）。
func Static() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
