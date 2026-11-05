package detect

import (
	"fmt"
	"strings"
	"time"

	"netsa/internal/model"
)

// 防火墙攻击防范判定与多源 DDoS 检测相互印证：
//   - 设备报告某个目的地址正在遭受洪泛（华为 ANTIATTACK、H3C ATK、深信服 DOS 日志）时记下来；之后按会话日志判断的
//     多源 DDoS（bhv-ddos）命中同一目的地址，说明不只是业务量突增，等级升为高危，并在证据中注明设备的判定；
//   - 设备的洪泛日志到达时，该目的地址正处在按会话日志判断的突增中，证据里注明来源数与事件量（DDoSContext）。
// 设备的 SYN 洪泛防护常在建立会话之前就丢弃报文，会话日志里看不到突增，这时只有设备的判定（没有来源也照样告警）。

const (
	devFloodWindow = 10 * time.Minute // 两种判定相隔多久之内视为同一次攻击
	maxDevFloods   = 5000
)

type devFlood struct {
	name string
	at   time.Time
}

// IsDeviceFlood 判断命中是不是设备给出的洪泛判定（防火墙攻击防范、IPS 的 DoS 类告警）。
func IsDeviceFlood(h *model.Hit) bool {
	return h.Category == CatFlood && strings.HasPrefix(h.RuleID, "dev-")
}

// noteDeviceFlood 记录设备报告的洪泛（调用方持锁）。
func (b *Behavior) noteDeviceFlood(ev *model.Event, ruleHits []model.Hit) {
	if ev.DstIP == "" {
		return
	}
	for i := range ruleHits {
		if !IsDeviceFlood(&ruleHits[i]) {
			continue
		}
		if b.devFloods == nil || len(b.devFloods) >= maxDevFloods {
			b.devFloods = map[string]devFlood{}
		}
		name := strings.TrimPrefix(ruleHits[i].Name, "设备告警: ")
		b.devFloods[ev.DstIP] = devFlood{name: name, at: ev.Time}
		return
	}
}

// deviceFloodNear 返回设备在 t 前后报告过的、针对该目的地址的洪泛（调用方持锁）。
func (b *Behavior) deviceFloodNear(dst string, t time.Time) (devFlood, bool) {
	d, ok := b.devFloods[dst]
	if !ok || t.Sub(d.at) > devFloodWindow || d.at.Sub(t) > devFloodWindow {
		return devFlood{}, false
	}
	return d, true
}

// DDoSContext 返回目的地址当前按会话日志判断的突增情况（没有突增时为空），用于补充设备洪泛判定的证据。
func (b *Behavior) DDoSContext(dst string, t time.Time) string {
	if b == nil || dst == "" {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, d := range b.dsts {
		if k.ip != dst || !d.surge || t.Sub(d.start) > 2*b.th.FwWindow || d.start.Sub(t) > devFloodWindow {
			continue
		}
		return fmt.Sprintf("按会话日志同时检测到该地址 %d 端口的连接突增（%s内 %d 条、%d 个以上来源）", k.port, fmtDur(b.th.FwWindow), d.n, d.nSrcs)
	}
	return ""
}

// pruneDevFloods 清理过期的设备洪泛记录（调用方持锁）。
func (b *Behavior) pruneDevFloods(now time.Time) {
	for k, d := range b.devFloods {
		if outside(now, d.at, time.Hour) {
			delete(b.devFloods, k)
		}
	}
}
