package detect

// acMatcher 是 Aho-Corasick 多模式匹配自动机：一次扫描文本即可找出全部规则预过滤字面量的出现位置，
// 代替对每条规则逐个 strings.Contains，使无害请求的检测开销与规则数量基本无关。
// 转移表按字面量实际用到的字节压缩字母表，避免 256 路稠密表占用过多内存。
type acMatcher struct {
	alpha [256]uint8 // 字节 → 压缩字母表下标（0 表示未出现在任何字面量中）
	width int        // 字母表大小（含 0）
	next  []int32    // node*width + c → 下一状态（已补全为 DFA）
	out   [][]int32  // 状态 → 在此结束的字面量编号（已合并失败链上的输出）
	lens  []int      // 字面量编号 → 长度
}

func newACMatcher(lits []string) *acMatcher {
	m := &acMatcher{width: 1}
	for _, l := range lits {
		for i := 0; i < len(l); i++ {
			if m.alpha[l[i]] == 0 {
				m.alpha[l[i]] = uint8(m.width)
				m.width++
			}
		}
		m.lens = append(m.lens, len(l))
	}
	// 构建 trie
	m.next = make([]int32, m.width)
	m.out = [][]int32{nil}
	for id, l := range lits {
		node := int32(0)
		for i := 0; i < len(l); i++ {
			c := int32(m.alpha[l[i]])
			nx := m.next[int(node)*m.width+int(c)]
			if nx == 0 {
				nx = int32(len(m.out))
				m.out = append(m.out, nil)
				m.next = append(m.next, make([]int32, m.width)...)
				m.next[int(node)*m.width+int(c)] = nx
			}
			node = nx
		}
		m.out[node] = append(m.out[node], int32(id))
	}
	// BFS 计算失败指针并补全转移表
	fail := make([]int32, len(m.out))
	queue := make([]int32, 0, len(m.out))
	for c := 1; c < m.width; c++ {
		if nx := m.next[c]; nx != 0 {
			queue = append(queue, nx)
		}
	}
	for qi := 0; qi < len(queue); qi++ {
		node := queue[qi]
		m.out[node] = append(m.out[node], m.out[fail[node]]...)
		for c := 1; c < m.width; c++ {
			idx := int(node)*m.width + c
			if nx := m.next[idx]; nx != 0 {
				fail[nx] = m.next[int(fail[node])*m.width+c]
				queue = append(queue, nx)
			} else {
				m.next[idx] = m.next[int(fail[node])*m.width+c]
			}
		}
	}
	return m
}

// bitset 是固定位数的位图。
type bitset []uint64

func (b bitset) set(i int32)      { b[i>>6] |= 1 << (uint(i) & 63) }
func (b bitset) has(i int32) bool { return b[i>>6]&(1<<(uint(i)&63)) != 0 }
func (b bitset) clear() {
	for i := range b {
		b[i] = 0
	}
}
