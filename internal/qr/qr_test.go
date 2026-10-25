package qr

import (
	"bytes"
	"strings"
	"testing"
)

// ISO/IEC 18004 与常见教程中的已知向量：“HELLO WORLD” 1-M 的数据码字与纠错码字。
func TestReedSolomon(t *testing.T) {
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}
	if got := rsRemainder(data, rsDivisor(10)); !bytes.Equal(got, want) {
		t.Fatalf("纠错码字: %v", got)
	}
}

func TestFormatAndVersionBits(t *testing.T) {
	want := []string{"101010000010010", "101000100100101", "101111001111100", "101101101001011",
		"100010111111001", "100000011001110", "100111110010111", "100101010100000"}
	for m, w := range want {
		got := ""
		for i := 14; i >= 0; i-- {
			got += string(rune('0' + formatBits(m)>>i&1))
		}
		if got != w {
			t.Errorf("M 掩码 %d 的格式信息: %s，期望 %s", m, got, w)
		}
	}
	if v := versionBits(7); v != 0x07C94 {
		t.Fatalf("版本 7 的版本信息: %x", v)
	}
	if v := versionBits(10); v != 0x0A4D3 {
		t.Fatalf("版本 10 的版本信息: %x", v)
	}
}

// decode 按与编码无关的步骤读回数据：从矩阵读取格式信息确定掩码，去掩码后按之字形顺序读取码字，
// 用纠错码校验每个块（余数为零），再解交织得到数据。
func decode(t *testing.T, c *Code) []byte {
	t.Helper()
	n := c.Size
	f := 0
	for i := 14; i >= 9; i-- {
		f = f<<1 | b2i(c.Dark(14-i, 8))
	}
	f = f<<1 | b2i(c.Dark(7, 8))
	f = f<<1 | b2i(c.Dark(8, 8))
	f = f<<1 | b2i(c.Dark(8, 7))
	for i := 5; i >= 0; i-- {
		f = f<<1 | b2i(c.Dark(8, i))
	}
	mask := -1
	for m := 0; m < 8; m++ {
		if formatBits(m) == f {
			mask = m
		}
	}
	if mask < 0 {
		t.Fatalf("格式信息无效: %015b", f)
	}
	// 用一个只画功能图形的空白码确定数据区
	ref := &Code{Version: c.Version, Size: n, mod: grid(n), fn: grid(n)}
	ref.drawFunctions()
	var bits []bool
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < n; vert++ {
			for j := 0; j < 2; j++ {
				x, y := right-j, vert
				if (right+1)&2 == 0 {
					y = n - 1 - vert
				}
				if !ref.fn[y][x] {
					bits = append(bits, c.Dark(x, y) != maskBit(mask, x, y))
				}
			}
		}
	}
	raw := make([]byte, rawModules(c.Version)/8)
	for i := range raw {
		for k := 0; k < 8; k++ {
			if bits[i*8+k] {
				raw[i] |= 0x80 >> k
			}
		}
	}
	nb, ecc := numBlocks[c.Version], eccPerBlock[c.Version]
	short := nb - len(raw)%nb
	shortLen := len(raw) / nb
	blocks := make([][]byte, nb)
	k := 0
	for i := 0; i <= shortLen; i++ {
		for j := 0; j < nb; j++ {
			if i != shortLen-ecc || j >= short {
				blocks[j] = append(blocks[j], raw[k])
				k++
			}
		}
	}
	var data []byte
	div := rsDivisor(ecc)
	for j, b := range blocks {
		d := b[:len(b)-ecc]
		if !bytes.Equal(rsRemainder(d, div), b[len(b)-ecc:]) {
			t.Fatalf("第 %d 块纠错码校验失败", j)
		}
		data = append(data, d...)
	}
	// 解析字节模式
	get := func(pos, n int) int {
		v := 0
		for i := 0; i < n; i++ {
			v = v<<1 | int(data[(pos+i)/8]>>(7-(pos+i)%8)&1)
		}
		return v
	}
	if get(0, 4) != 4 {
		t.Fatalf("模式指示符: %d", get(0, 4))
	}
	cl := 8
	if c.Version >= 10 {
		cl = 16
	}
	cnt := get(4, cl)
	out := make([]byte, cnt)
	for i := range out {
		out[i] = byte(get(4+cl+i*8, 8))
	}
	return out
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestEncodeRoundTrip(t *testing.T) {
	for _, s := range []string{"A", "https://example.com/",
		"otpauth://totp/netsa:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=netsa&algorithm=SHA1&digits=6&period=30",
		strings.Repeat("中文与 ASCII 混合内容 0123456789 ", 4), strings.Repeat("x", 213)} {
		c, err := Encode([]byte(s))
		if err != nil {
			t.Fatalf("%d 字节: %v", len(s), err)
		}
		if got := string(decode(t, c)); got != s {
			t.Fatalf("版本 %d 掩码 %d 读回不一致: %q", c.Version, c.Mask, got)
		}
		// 位置探测图形
		for _, p := range [][2]int{{0, 0}, {c.Size - 7, 0}, {0, c.Size - 7}} {
			if !c.Dark(p[0], p[1]) || !c.Dark(p[0]+3, p[1]+3) || c.Dark(p[0]+1, p[1]+1) {
				t.Fatalf("位置探测图形错误（版本 %d）", c.Version)
			}
		}
		if svg := c.SVG(4); !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "M4 4h1v1h-1z") {
			t.Fatal("SVG")
		}
	}
	if _, err := Encode(make([]byte, 214)); err != ErrTooLong {
		t.Fatal("超出容量应报错")
	}
	if c, _ := Encode([]byte(strings.Repeat("y", 150))); c.Version < 7 {
		t.Fatal("应使用带版本信息的版本")
	}
}
