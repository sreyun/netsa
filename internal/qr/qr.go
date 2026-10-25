// Package qr 生成二维码（ISO/IEC 18004）：字节模式、纠错等级 M、版本 1 ~ 10（最多 213 字节），输出 SVG。
// 用于双因素认证绑定时展示 otpauth:// 链接，页面无需引入第三方脚本。
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// 纠错等级 M 的每块纠错码字数与块数（下标为版本号）。
var (
	eccPerBlock = [...]int{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26}
	numBlocks   = [...]int{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5}
	alignPos    = [...][]int{nil, nil, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50}}
)

const eclM = 0 // 格式信息中 M 的编码

// ErrTooLong 表示内容超过版本 10 的容量。
var ErrTooLong = errors.New("二维码内容过长")

// Code 是二维码矩阵。
type Code struct {
	Size    int
	Version int
	Mask    int
	mod     [][]bool // [y][x]，true 为深色
	fn      [][]bool // 功能图形（不放数据、不加掩码）
}

func rawModules(ver int) int {
	r := (16*ver+128)*ver + 64
	if ver >= 2 {
		n := ver/7 + 2
		r -= (25*n-10)*n - 55
		if ver >= 7 {
			r -= 36
		}
	}
	return r
}

func dataCapacity(ver int) int { return rawModules(ver)/8 - eccPerBlock[ver]*numBlocks[ver] }

// Encode 生成二维码。
func Encode(data []byte) (*Code, error) {
	ver := 0
	for v := 1; v <= 10; v++ {
		head := 4 + 8
		if v >= 10 {
			head = 4 + 16
		}
		if (head+8*len(data)+7)/8 <= dataCapacity(v) {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ErrTooLong
	}
	// 数据位流：模式指示符 0100（字节）+ 字符计数 + 数据 + 终止符 + 补齐
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, v>>i&1 == 1)
		}
	}
	put(4, 4)
	if ver >= 10 {
		put(len(data), 16)
	} else {
		put(len(data), 8)
	}
	for _, b := range data {
		put(int(b), 8)
	}
	capBits := dataCapacity(ver) * 8
	put(0, min(4, capBits-len(bits)))
	put(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	cw := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			cw[i/8] |= 0x80 >> (i % 8)
		}
	}
	c := &Code{Version: ver, Size: ver*4 + 17}
	c.mod, c.fn = grid(c.Size), grid(c.Size)
	c.drawFunctions()
	c.drawCodewords(interleave(cw, ver))
	// 选择惩罚分最低的掩码
	best, bestScore := 0, -1
	for m := 0; m < 8; m++ {
		c.applyMask(m)
		c.drawFormat(m)
		if s := c.penalty(); bestScore < 0 || s < bestScore {
			best, bestScore = m, s
		}
		c.applyMask(m) // 异或两次即撤销
	}
	c.Mask = best
	c.applyMask(best)
	c.drawFormat(best)
	return c, nil
}

func grid(n int) [][]bool {
	g := make([][]bool, n)
	for i := range g {
		g[i] = make([]bool, n)
	}
	return g
}

func (c *Code) set(x, y int, dark bool) {
	c.mod[y][x] = dark
	c.fn[y][x] = true
}

// Dark 返回 (x, y) 处是否为深色模块。
func (c *Code) Dark(x, y int) bool { return c.mod[y][x] }

func (c *Code) drawFunctions() {
	n := c.Size
	for i := 0; i < n; i++ { // 定位图形之间的时序图形
		c.set(6, i, i%2 == 0)
		c.set(i, 6, i%2 == 0)
	}
	for _, p := range [][2]int{{3, 3}, {n - 4, 3}, {3, n - 4}} { // 位置探测图形与分隔符
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := p[0]+dx, p[1]+dy
				if x >= 0 && x < n && y >= 0 && y < n {
					d := max(abs(dx), abs(dy))
					c.set(x, y, d != 2 && d != 4)
				}
			}
		}
	}
	pos := alignPos[c.Version]
	for i := range pos {
		for j := range pos {
			if i == 0 && j == 0 || i == 0 && j == len(pos)-1 || i == len(pos)-1 && j == 0 {
				continue // 与位置探测图形重叠
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					c.set(pos[i]+dx, pos[j]+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	c.drawFormat(0) // 先占位，选定掩码后重写
	if c.Version >= 7 {
		bits := versionBits(c.Version)
		for i := 0; i < 18; i++ {
			dark := bits>>i&1 == 1
			a, b := n-11+i%3, i/3
			c.set(a, b, dark)
			c.set(b, a, dark)
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// formatBits 返回纠错等级 M 与掩码对应的 15 位格式信息（BCH(15,5)，异或 0x5412）。
func formatBits(mask int) int {
	data := eclM<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	return (data<<10 | rem&0x3FF) ^ 0x5412
}

// versionBits 返回 18 位版本信息（BCH(18,6)）。
func versionBits(ver int) int {
	rem := ver
	for i := 0; i < 12; i++ {
		rem = rem<<1 ^ (rem>>11)*0x1F25
	}
	return ver<<12 | rem&0xFFF
}

func (c *Code) drawFormat(mask int) {
	bits, n := formatBits(mask), c.Size
	bit := func(i int) bool { return bits>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		c.set(8, i, bit(i))
	}
	c.set(8, 7, bit(6))
	c.set(8, 8, bit(7))
	c.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		c.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		c.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		c.set(8, n-15+i, bit(i))
	}
	c.set(8, n-8, true) // 固定的深色模块
}

// ---------------- Reed-Solomon ----------------

func gfMul(x, y byte) byte {
	var z int
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x11D
		z ^= int(y>>i&1) * int(x)
	}
	return byte(z)
}

func rsDivisor(degree int) []byte {
	r := make([]byte, degree)
	r[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := range r {
			r[j] = gfMul(r[j], root)
			if j+1 < len(r) {
				r[j] ^= r[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return r
}

func rsRemainder(data, div []byte) []byte {
	r := make([]byte, len(div))
	for _, b := range data {
		f := b ^ r[0]
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i := range r {
			r[i] ^= gfMul(div[i], f)
		}
	}
	return r
}

// interleave 分块计算纠错码并交织。
func interleave(data []byte, ver int) []byte {
	nb, ecc := numBlocks[ver], eccPerBlock[ver]
	raw := rawModules(ver) / 8
	short := nb - raw%nb
	shortLen := raw / nb
	div := rsDivisor(ecc)
	blocks := make([][]byte, nb)
	k := 0
	for i := 0; i < nb; i++ {
		n := shortLen - ecc
		if i >= short {
			n++
		}
		dat := data[k : k+n]
		k += n
		blk := make([]byte, shortLen+1)
		copy(blk, dat)
		copy(blk[len(blk)-ecc:], rsRemainder(dat, div))
		blocks[i] = blk
	}
	out := make([]byte, 0, raw)
	for i := 0; i < len(blocks[0]); i++ {
		for j := range blocks {
			if i != shortLen-ecc || j >= short { // 短块在该位置没有数据
				out = append(out, blocks[j][i])
			}
		}
	}
	return out
}

func (c *Code) drawCodewords(data []byte) {
	n, i := c.Size, 0
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5 // 跳过垂直时序图形
		}
		for vert := 0; vert < n; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = n - 1 - vert // 向上
				}
				if !c.fn[y][x] && i < len(data)*8 {
					c.mod[y][x] = data[i>>3]>>(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func maskBit(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	}
	return ((x+y)%2+x*y%3)%2 == 0
}

func (c *Code) applyMask(m int) {
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if !c.fn[y][x] && maskBit(m, x, y) {
				c.mod[y][x] = !c.mod[y][x]
			}
		}
	}
}

// penalty 计算掩码惩罚分（规则 1、2、4：连续同色、2×2 同色块、深浅比例）。
func (c *Code) penalty() int {
	n, p, dark := c.Size, 0, 0
	for y := 0; y < n; y++ {
		for _, horiz := range []bool{true, false} {
			run, last := 0, false
			for x := 0; x < n; x++ {
				v := c.mod[y][x]
				if !horiz {
					v = c.mod[x][y]
				}
				if x > 0 && v == last {
					run++
					if run == 5 {
						p += 3
					} else if run > 5 {
						p++
					}
				} else {
					run, last = 1, v
				}
			}
		}
		for x := 0; x < n; x++ {
			if c.mod[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n && c.mod[y][x] == c.mod[y][x+1] && c.mod[y][x] == c.mod[y+1][x] && c.mod[y][x] == c.mod[y+1][x+1] {
				p += 3
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10)+total-1)/total - 1
	return p + max(k, 0)*10
}

// SVG 返回二维码的 SVG（含 4 个模块宽的静区），scale 为每个模块的像素数。
func (c *Code) SVG(scale int) string {
	q := 4
	w := (c.Size + 2*q) * scale
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, w, w, c.Size+2*q, c.Size+2*q)
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.mod[y][x] {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+q, y+q)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}
