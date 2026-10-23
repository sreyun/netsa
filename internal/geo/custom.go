package geo

import (
	"net/netip"
	"sort"
	"strings"

	"netsa/internal/config"
)

// Custom 是用户自定义的网段位置库（内网办公区、分支机构、合作方出口等），按最长前缀匹配，
// 优先级高于所有定位库：内网攻击源可以落到具体的办公地点，而不是笼统的“内网”。
type Custom struct {
	nets []customNet // 按前缀长度降序，首个命中即最长前缀
}

type customNet struct {
	prefix netip.Prefix
	sr     SourceResult
}

// NewCustom 根据配置创建自定义网段库；列表为空时返回 nil。
func NewCustom(list []config.CustomLocation) *Custom {
	c := &Custom{}
	for _, l := range list {
		s := strings.TrimSpace(l.CIDR)
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				continue
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		cc := strings.ToUpper(l.CountryCode)
		if cc == "" && strings.HasPrefix(l.Country, "中国") {
			cc = "CN"
		}
		c.nets = append(c.nets, customNet{prefix: p.Masked(), sr: SourceResult{
			Source: "custom", Label: l.Name, Country: l.Country, CountryCode: cc, Province: l.Province,
			City: l.City, ISP: l.ISP, Lat: l.Lat, Lon: l.Lon,
		}})
	}
	if len(c.nets) == 0 {
		return nil
	}
	sort.SliceStable(c.nets, func(i, j int) bool { return c.nets[i].prefix.Bits() > c.nets[j].prefix.Bits() })
	return c
}

func (*Custom) Name() string { return "custom" }

// Len 返回自定义网段数量。
func (c *Custom) Len() int {
	if c == nil {
		return 0
	}
	return len(c.nets)
}

func (c *Custom) Lookup(addr netip.Addr) (*SourceResult, error) {
	if c == nil {
		return nil, nil
	}
	for i := range c.nets {
		if c.nets[i].prefix.Contains(addr) {
			sr := c.nets[i].sr
			return &sr, nil
		}
	}
	return nil, nil
}
