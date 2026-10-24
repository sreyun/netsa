// Package safe 提供异常保护：处理日志等外部数据时，单条畸形数据触发的程序异常只影响该条数据，
// 不会导致整个服务退出。
package safe

import (
	"log"
	"runtime/debug"
	"sync/atomic"
)

var count atomic.Int64

// Count 返回累计捕获的异常次数。
func Count() int64 { return count.Load() }

// Report 记录一次被捕获的异常。前 5 次输出完整调用栈，之后每 1000 次输出一次计数，避免刷屏。
// 用法：defer func() { if r := recover(); r != nil { safe.Report("检测", r) } }()
func Report(where string, r any) {
	n := count.Add(1)
	switch {
	case n <= 5:
		log.Printf("[safe] %s 时发生异常（已跳过该条数据）: %v\n%s", where, r, debug.Stack())
	case n%1000 == 0:
		log.Printf("[safe] 已累计跳过 %d 条触发异常的数据，最近一次: %s: %v", n, where, r)
	}
}
