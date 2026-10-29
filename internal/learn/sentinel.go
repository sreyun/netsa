package learn

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"netsa/internal/auth"
	"netsa/internal/geo"
	"netsa/internal/model"
)

// 平台自身的行为基线：态势感知平台本身握有全网日志与处置权限，是攻击者的高价值目标。
// 从审计记录中学习每个账号的常用登录网段与时段，发现异常登录、批量导出与高危配置变更时告警。

// userBase 是一个平台账号的登录行为基线。
type userBase struct {
	Logins int            `json:"logins"`
	Nets   map[string]int `json:"nets"`  // 登录来源网段（IPv4 /24、IPv6 /48）→ 次数（最多 50 个）
	Hours  [24]int        `json:"hours"` // 登录时段分布（服务器时区）
}

// Anomaly 是平台自身的一次异常操作。
type Anomaly struct {
	Time     time.Time      `json:"time"`
	Kind     string         `json:"kind"` // new_net / odd_hour / login_fail / bulk_export / sensitive
	User     string         `json:"user"`
	IP       string         `json:"ip"`
	Severity model.Severity `json:"severity"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail"`
}

type sentinelState struct {
	exports map[string][]time.Time // 账号 → 近 1 小时的导出时间
	fails   map[string][]time.Time // 账号 → 近 1 小时的登录失败时间
	alerted map[string]time.Time   // 去重键 → 上次告警时间
}

const (
	learnLogins  = 5  // 账号登录满 5 次后才按「新地址」告警（学习期）
	hourLogins   = 20 // 登录满 20 次后才按「非常用时段」告警
	exportBurst  = 5  // 1 小时内同一账号的导出次数
	failBurst    = 10 // 1 小时内同一账号的登录失败次数
	maxNets      = 50
	maxAnomalies = 500
	maxUsers     = 2000
)

// netKey 返回地址所在的网段（IPv4 /24、IPv6 /48），同一网段内变化（DHCP）不算新地址。
func netKey(ip string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ip
	}
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, _ := a.Prefix(bits)
	return p.String()
}

// within 返回 list 中不早于 since 的时间。
func within(list []time.Time, since time.Time) []time.Time {
	out := list[:0]
	for _, t := range list {
		if !t.Before(since) {
			out = append(out, t)
		}
	}
	return out
}

// ObserveAudit 学习一条审计记录，返回发现的异常（调用方负责推送）。
func (l *Learner) ObserveAudit(r auth.Record) []Anomaly {
	if l == nil || !l.opt.Sentinel || r.User == "" {
		return nil
	}
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sent.exports == nil {
		l.sent = sentinelState{exports: map[string][]time.Time{}, fails: map[string][]time.Time{}, alerted: map[string]time.Time{}}
	}
	var out []Anomaly
	add := func(key string, a Anomaly) {
		if last, ok := l.sent.alerted[key]; ok && r.Time.Sub(last) < time.Hour {
			return
		}
		l.sent.alerted[key] = r.Time
		if len(l.sent.alerted) > 10000 {
			for k, t := range l.sent.alerted {
				if r.Time.Sub(t) > time.Hour {
					delete(l.sent.alerted, k)
				}
			}
		}
		a.Time, a.User, a.IP = r.Time, r.User, r.IP
		out = append(out, a)
		l.anomalies = append(l.anomalies, a)
		if len(l.anomalies) > maxAnomalies {
			l.anomalies = append([]Anomaly(nil), l.anomalies[len(l.anomalies)-maxAnomalies:]...)
		}
		l.dirty = true
	}
	hourAgo := r.Time.Add(-time.Hour)

	switch {
	case r.Action == "" && r.OK: // 登录成功
		b := l.users[r.User]
		if b == nil {
			if len(l.users) >= maxUsers {
				return nil
			}
			b = &userBase{Nets: map[string]int{}}
			l.users[r.User] = b
		}
		nk, h := netKey(r.IP), r.Time.Hour()
		if _, known := b.Nets[nk]; !known && b.Logins >= learnLogins && r.IP != "" {
			sev, where := model.SevMedium, "内网"
			if a, err := netip.ParseAddr(r.IP); err == nil && geo.IsPublic(a) {
				sev, where = model.SevHigh, "公网"
			}
			add("net|"+r.User+"|"+nk, Anomaly{Kind: "new_net", Severity: sev, Title: "平台账号 " + r.User + " 从新地址登录",
				Detail: "来源 " + r.IP + "（" + where + "，网段 " + nk + "）此前从未出现，该账号已登录 " + strconv.Itoa(b.Logins) + " 次，常用网段 " + topNets(b.Nets, 3) +
					"；如非本人操作，请立即修改密码并吊销会话"})
		}
		if b.Logins >= hourLogins && b.Hours[h] == 0 && b.Hours[(h+23)%24] == 0 && b.Hours[(h+1)%24] == 0 {
			add("hour|"+r.User+"|"+strconv.Itoa(h), Anomaly{Kind: "odd_hour", Severity: model.SevMedium, Title: "平台账号 " + r.User + " 在非常用时段登录",
				Detail: "登录时间 " + r.Time.Format("15:04") + "，该账号此前 " + strconv.Itoa(b.Logins) + " 次登录从未出现在该时段前后；来源 " + r.IP})
		}
		b.Logins++
		b.Hours[h]++
		if _, ok := b.Nets[nk]; ok || len(b.Nets) < maxNets {
			b.Nets[nk]++
		}
		l.dirty = true
	case r.Action == "": // 登录失败
		list := append(within(l.sent.fails[r.User], hourAgo), r.Time)
		l.sent.fails[r.User] = list
		if len(list) >= failBurst {
			add("fail|"+r.User, Anomaly{Kind: "login_fail", Severity: model.SevHigh, Title: "平台账号 " + r.User + " 疑似被暴力破解",
				Detail: "1 小时内登录失败 " + strconv.Itoa(len(list)) + " 次，最近来源 " + r.IP + "（" + r.Reason + "）；平台已按来源与账号自动锁定，请核实是否为本人操作"})
		}
	case !r.OK:
		return nil
	case strings.Contains(r.Action, "导出") || r.Action == "下载分析报告":
		list := append(within(l.sent.exports[r.User], hourAgo), r.Time)
		l.sent.exports[r.User] = list
		if len(list) >= exportBurst {
			add("export|"+r.User, Anomaly{Kind: "bulk_export", Severity: model.SevMedium, Title: "平台账号 " + r.User + " 短时间内大量导出数据",
				Detail: "1 小时内导出 " + strconv.Itoa(len(list)) + " 次，最近一次：" + r.Action + " " + r.Detail + "；请核实是否为正常取证，防止日志与告警数据外泄"})
		}
	default:
		if title, sev := sensitive(r.Action, r.Detail); title != "" {
			add("sens|"+r.User+"|"+r.Action+"|"+r.Detail, Anomaly{Kind: "sensitive", Severity: sev, Title: title,
				Detail: "操作人 " + r.User + "（" + r.IP + "）：" + r.Action + " " + r.Detail})
		}
	}
	return out
}

// sensitive 判断操作是否属于会削弱平台安全或检测能力的高危变更。
func sensitive(action, detail string) (string, model.Severity) {
	switch action {
	case "关闭双因素认证", "重置双因素认证":
		return "平台账号的双因素认证被关闭 / 重置", model.SevHigh
	case "创建账号", "修改账号":
		if strings.Contains(detail, "admin") || strings.Contains(detail, "管理员") {
			return "新增或提升了平台管理员账号", model.SevHigh
		}
	case "创建 API 令牌":
		if strings.Contains(detail, "admin") {
			return "创建了管理员权限的 API 令牌", model.SevHigh
		}
	case "添加误报抑制":
		// 没有指定检测规则、只按来源网段或攻击类型抑制：范围较宽，可能掩盖真实攻击
		if !strings.Contains(detail, "规则 ") && !strings.Contains(detail, "目标 ") {
			return "添加了范围较宽的误报抑制（可能掩盖真实攻击）", model.SevMedium
		}
	case "syslog 发送端白名单":
		if strings.HasPrefix(detail, "关闭") {
			return "关闭了 syslog 发送端白名单（任何设备都可以发送日志）", model.SevMedium
		}
	case "删除告警机器人":
		return "删除了告警推送机器人", model.SevMedium
	}
	return "", 0
}

func topNets(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	for i := 1; i < len(list); i++ { // 数量很少，插入排序
		for j := i; j > 0 && (list[j].v > list[j-1].v || list[j].v == list[j-1].v && list[j].k < list[j-1].k); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	var out []string
	for i := 0; i < len(list) && i < n; i++ {
		out = append(out, list[i].k)
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, "、")
}

// Sink 包装审计链：记录照常写入下一级（防篡改审计链），同时学习平台账号的行为基线；
// 发现异常时把异常本身也写入审计链，并回调 Notify 推送（Notify 必须是非阻塞的：调用方可能持有账号管理的锁）。
type Sink struct {
	Next   auth.AuditSink
	L      *Learner
	Notify func(Anomaly)
}

// AppendAudit 实现 auth.AuditSink。
func (s *Sink) AppendAudit(r auth.Record) {
	if s.Next != nil {
		s.Next.AppendAudit(r)
	}
	for _, a := range s.L.ObserveAudit(r) {
		if s.Next != nil {
			s.Next.AppendAudit(auth.Record{Time: a.Time, User: "系统", IP: a.IP, Action: "平台安全异常", Detail: a.Title + "：" + a.Detail, OK: true})
		}
		if s.Notify != nil {
			s.Notify(a)
		}
	}
}
