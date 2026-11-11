package geo

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Reload 检查各离线库文件是否被替换，有更新时重新加载并刷新缓存中全部地址的定位结果，
// 返回发生更新的数据源名称。
func (r *Resolver) Reload() ([]string, error) {
	var changed []string
	var errs []error
	for _, p := range r.opt.Providers {
		rl, ok := p.(Reloader)
		if !ok {
			continue
		}
		ok, err := rl.Reload()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
		}
		if ok {
			changed = append(changed, p.Name())
		}
	}
	if len(changed) > 0 {
		r.refresh()
	}
	return changed, errors.Join(errs...)
}

// SetCustom 替换自定义网段库并刷新缓存。
func (r *Resolver) SetCustom(c *Custom) {
	r.custom.Store(c)
	r.refresh()
}

// Reclassify 在内网网段变化后（自学习识别出新网段）按当前网段重新定位缓存中的全部地址。
// 不调用时缓存里仍是旧的归属，Relocate 会原样返回，已有攻击源要等缓存淘汰或重启才更新。
func (r *Resolver) Reclassify() { r.refresh() }

// refresh 用当前离线库与内网网段重新定位缓存中的全部地址。逐个加锁，不阻塞实时定位。
// 画像侧的更新由调用方通过 Store.RefreshGeo + Relocate 完成。
func (r *Resolver) refresh() {
	r.mu.Lock()
	ips := make([]string, 0, len(r.cache))
	for ip := range r.cache {
		ips = append(ips, ip)
	}
	r.mu.Unlock()
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		private := isPrivate(addr)
		local := r.lookupLocal(addr, private)
		r.mu.Lock()
		if e := r.cache[ip]; e != nil {
			if private != e.private {
				// 归属变了（划入或移出内网）：在线定位结果不再适用，移出内网后可以重新补全
				e.online, e.enriched = nil, false
				e.onlineTries, e.onlineAt, e.rdnsDone = 0, time.Time{}, false
			}
			e.private, e.local = private, local
			e.info = r.merge(ip, e)
		}
		r.mu.Unlock()
	}
}

// Relocate 返回地址按当前离线库的定位结果。缓存中没有该地址时（如从快照恢复的画像），
// 以离线库重新定位，并沿用 old 中已完成的在线溯源与 rDNS 结果，避免重复查询。
func (r *Resolver) Relocate(ip string, old *Info) *Info {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return old
	}
	addr = addr.Unmap()
	r.mu.Lock()
	if e := r.cache[ip]; e != nil {
		info := e.info
		r.mu.Unlock()
		return info
	}
	r.mu.Unlock()
	e := &entry{private: isPrivate(addr)}
	e.local = r.lookupLocal(addr, e.private)
	if old != nil && !e.private {
		// 在线定位的结果只要有就沿用（反向解析失败时 Enriched 为 false，但在线结果是完整的）
		for i := range old.Sources {
			if r.opt.Online != nil && old.Sources[i].Source == r.opt.Online.Name() {
				sr := old.Sources[i]
				e.online = &sr
			}
		}
		if old.Enriched {
			// 没有在线结果的（当时接口失败或没有返回）保持可重试：Enrich 再次调用时补查
			e.rdns, e.enriched, e.rdnsDone = old.RDNS, true, true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.cache[ip]; cur != nil {
		return cur.info
	}
	if len(r.cache) >= r.opt.CacheSize {
		r.evict()
	}
	e.info = r.merge(ip, e)
	r.cache[ip] = e
	return e.info
}

// SameLocation 判断两次定位结果在展示层面是否一致。
func SameLocation(a, b *Info) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Location() == b.Location() && a.Lat == b.Lat && a.Lon == b.Lon && a.ASN == b.ASN &&
		a.CoordSource == b.CoordSource && a.Confidence == b.Confidence && a.Private == b.Private
}
