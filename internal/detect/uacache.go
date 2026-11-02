package detect

import (
	"sync"
	"sync/atomic"
)

// UA 规则的匹配结果缓存。
//
// 针对 User-Agent 的规则（扫描器、测绘引擎、脚本客户端）只取决于 UA 文本本身，而真实流量中的 UA 高度重复：
// 扫描器与脚本会用同一个 UA 发出成千上万次请求。其中漏洞扫描器规则是约 70 个工具名的大分支正则，
// 预过滤通过后每次执行约数微秒，在演示数据上占全部正则耗时的六成。按 UA 缓存每条 UA 规则的命中位置后，
// 重复的 UA 不再执行这些正则；方法、响应结果等与单次请求相关的条件仍逐次判断，检测结果完全一致。
const (
	uaCacheMax = 8192 // 条目上限：满后整体换新（随机生成的 UA 只会导致重算，不会让内存无限增长）
	uaCacheLen = 512  // 超长 UA 不缓存
)

type uaCache struct {
	m atomic.Pointer[sync.Map] // 小写 UA → []int32：每条 UA 规则的命中位置（start, end），未命中为 -1
	n atomic.Int64
}

func newUACache() *uaCache {
	c := &uaCache{}
	c.m.Store(new(sync.Map))
	return c
}

func (c *uaCache) get(ua string) ([]int32, bool) {
	v, ok := c.m.Load().Load(ua)
	if !ok {
		return nil, false
	}
	return v.([]int32), true
}

func (c *uaCache) put(ua string, locs []int32) {
	if c.n.Add(1) > uaCacheMax {
		c.m.Store(new(sync.Map))
		c.n.Store(0)
	}
	c.m.Load().Store(ua, locs)
}

// uaLocs 返回各 UA 规则在 ua 上的命中位置（顺序与 e.uaRules 一致）。segs 为本次请求的预过滤位图。
func (e *Engine) uaLocs(ua string, segs *[segCount]bitset) []int32 {
	cacheable := len(ua) <= uaCacheLen
	if cacheable {
		if v, ok := e.uac.get(ua); ok {
			return v
		}
	}
	locs := make([]int32, 2*len(e.uaRules))
	for s, idx := range e.uaRules {
		r := e.rules[idx]
		locs[2*s], locs[2*s+1] = -1, -1
		if r.needIDs != nil && e.ac != nil && !clausesPass(r.needIDs, segs[segUA]) {
			continue
		}
		if loc := r.re.FindStringIndex(ua); loc != nil {
			locs[2*s], locs[2*s+1] = int32(loc[0]), int32(loc[1])
		}
	}
	if cacheable {
		e.uac.put(ua, locs)
	}
	return locs
}
