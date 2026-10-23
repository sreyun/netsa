package geo

import (
	"errors"
	"fmt"
	"net/netip"
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

// refresh 用当前离线库重新定位缓存中的全部地址。逐个加锁，不阻塞实时定位。
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
		local := r.lookupLocal(addr, isPrivate(addr))
		r.mu.Lock()
		if e := r.cache[ip]; e != nil {
			e.local = local
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
	if old != nil && old.Enriched {
		for i := range old.Sources {
			if r.opt.Online != nil && old.Sources[i].Source == r.opt.Online.Name() {
				sr := old.Sources[i]
				e.online = &sr
			}
		}
		e.rdns, e.enriched = old.RDNS, true
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
