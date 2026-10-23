package pipeline

import (
	"strings"
	"testing"

	"netsa/internal/detect"
	"netsa/internal/parser"
)

// 攻击者可构造超长请求行，检测耗时应与长度近似线性，不能出现数量级的放大。
func BenchmarkInspectHugeURI(b *testing.B) {
	eng, _ := detect.NewEngine("", 1)
	p, _ := parser.NewAuto("auto", "")
	line := `203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "GET /a?x=` + strings.Repeat("A%25", 6000) + ` HTTP/1.1" 200 5 "-" "x"`
	ev, ok := p.Parse(line)
	if !ok {
		b.Fatal("parse")
	}
	b.SetBytes(int64(len(line)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Inspect(ev)
	}
}

func BenchmarkNewAuto(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parser.NewAuto("auto", "")
	}
}
