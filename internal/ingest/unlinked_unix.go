//go:build unix

package ingest

import (
	"os"
	"syscall"
)

// unlinked 判断已打开的文件是否已被删除（硬链接数为 0）。重命名（轮转）的文件链接数不变。
func unlinked(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 0
}
