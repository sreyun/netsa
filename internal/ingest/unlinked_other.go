//go:build !unix

package ingest

import "os"

// unlinked 在没有硬链接计数的平台上总是返回 false（Windows 上被打开的文件无法删除）。
func unlinked(os.FileInfo) bool { return false }
