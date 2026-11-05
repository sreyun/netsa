package pipeline

import (
	"path"
	"strings"
	"time"

	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/intel"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 流量日志的情报检查（P3-1）：
//   - TLS 客户端指纹（JA3 / JA4）命中情报：内网主机发起的连接按疑似木马 / 远控（恶意外连）处理，
//     外部来源按攻击工具的指纹处理（威胁情报）；
//   - TLS 握手的 SNI 命中域名情报：与 DNS 查询命中同样处理（加密连接不经过内网 DNS 时也能发现）；
//   - 传输的文件：哈希命中情报为恶意文件；内网主机在遭受攻击之后从攻击者、或攻击载荷写明的地址下载可执行文件、
//     脚本，即攻击载荷已落地（载荷下载，严重）。

// CatMalFile 是传输情报标记的恶意文件，CatPayload 是从攻击者地址下载的可执行文件 / 脚本。
const (
	CatMalFile = "恶意文件"
	CatPayload = "载荷下载"
)

// worstKind 返回多个情报中最严重的类别。
func (p *Pipeline) worstKind(names []string) string {
	kind, rank := intel.KindAttacker, -1
	for _, n := range names {
		if k := p.Intel.KindOf(n); domainRank[k] > rank {
			kind, rank = k, domainRank[k]
		}
	}
	return kind
}

// tlsIntelHit 检查 TLS 客户端指纹是否命中情报。
func (p *Pipeline) tlsIntelHit(ev *model.Event) (model.Hit, bool) {
	if p.Intel == nil || ev.TLSFinger == "" || ev.SrcIP == "" {
		return model.Hit{}, false
	}
	names := p.Intel.MatchFinger(ev.TLSFinger)
	if len(names) == 0 {
		return model.Hit{}, false
	}
	kind := p.worstKind(names)
	dst := ev.DstIP
	if ev.SNI != "" {
		dst = ev.SNI + "（" + ev.DstIP + "）"
	}
	h := model.Hit{RuleID: "intel-tls", Feeds: names, Result: model.ResultAllowed,
		Evidence: ev.SrcIP + " → " + dst + " 的 TLS 客户端指纹 " + ev.TLSFinger + " 命中 " + strings.Join(names, "、")}
	if ev.Reply == model.ReplyNone {
		h.Result = model.ResultFailed
	}
	if geo.IsPrivate(ev.SrcIP) && ev.DstIP != "" && !geo.IsPrivate(ev.DstIP) {
		// 内网主机作为客户端：恶意软件、远控木马的固定指纹
		h.Name, h.Category, h.Severity, h.Phase = "内网主机的 TLS 指纹命中情报（疑似木马 / 远控）", store.CatC2, model.SevHigh, model.PhasePersistence
		if kind == intel.KindAttacker || kind == intel.KindPhishing {
			h.Severity = model.SevMedium
		}
		return h, true
	}
	h.Name, h.Category, h.Severity, h.Phase = "攻击工具的 TLS 指纹（情报）", detect.CatIntel, model.SevMedium, model.PhaseRecon
	if kind == intel.KindAttacker {
		h.Severity = model.SevLow
	}
	return h, true
}

// fileHit 检查传输的文件（Zeek files.log）：哈希情报与攻击之后下载的载荷。SrcIP 为接收文件的主机，DstIP 为发送方。
func (p *Pipeline) fileHit(ev *model.Event, at time.Time) (model.Hit, bool) {
	f := ev.File
	if f == nil || ev.SrcIP == "" || ev.DstIP == "" {
		return model.Hit{}, false
	}
	desc := fileDesc(f) + "（" + ev.DstIP + " → " + ev.SrcIP + "）"
	if p.Intel != nil {
		if names := p.Intel.MatchHash(f.SHA256, f.SHA1, f.MD5); len(names) > 0 {
			sev := model.SevHigh
			if geo.IsPrivate(ev.SrcIP) && !geo.IsPrivate(ev.DstIP) {
				sev = model.SevCritical // 内网主机从公网下载了已知恶意文件
			}
			return model.Hit{RuleID: "intel-file", Name: "传输情报标记的恶意文件", Category: CatMalFile, Severity: sev, Phase: model.PhasePersistence,
				Result: model.ResultSuccess, Proven: true, Feeds: names, Evidence: desc + " 的哈希命中 " + strings.Join(names, "、")}, true
		}
	}
	if !geo.IsPrivate(ev.SrcIP) || geo.IsPrivate(ev.DstIP) || !executableFile(f) {
		return model.Hit{}, false
	}
	c := &p.cb
	c.mu.Lock()
	mp, inPayload := c.payload[ev.DstIP]
	ma, isAttacker := c.attackers[ev.DstIP]
	c.mu.Unlock()
	within := func(m attackMark) bool {
		d := at.Sub(m.at)
		return d >= -callbackSlack && d <= callbackWindow
	}
	var m attackMark
	switch {
	case inPayload && within(mp):
		m = mp
	case isAttacker && within(ma):
		m = ma
	default:
		return model.Hit{}, false
	}
	return model.Hit{RuleID: "payload-download", Name: "遭受攻击后从攻击者地址下载可执行文件（载荷落地）", Category: CatPayload, Severity: model.SevCritical,
		Phase: model.PhasePersistence, Result: model.ResultSuccess, Proven: true,
		Evidence: detect.Printable(desc+"："+ev.DstIP+" 此前对 "+m.target+" 发起过 "+m.name+"（来源 "+m.src+"），之后 "+ev.SrcIP+" 从该地址下载了这个文件", 400)}, true
}

func fileDesc(f *model.FileInfo) string {
	s := "文件"
	if f.Name != "" {
		s += " " + detect.Printable(f.Name, 80)
	}
	if f.Mime != "" {
		s += "（" + f.Mime + "）"
	}
	if f.SHA256 != "" {
		s += " SHA256 " + f.SHA256
	} else if f.MD5 != "" {
		s += " MD5 " + f.MD5
	}
	return s
}

// executableFile 判断是否为可执行文件或脚本。
func executableFile(f *model.FileInfo) bool {
	switch f.Mime {
	case "application/x-dosexec", "application/x-executable", "application/x-elf", "application/x-sharedlib", "application/x-mach-o-executable",
		"application/x-sh", "text/x-shellscript", "application/x-msdownload", "application/x-msi", "application/x-ms-shortcut",
		"application/x-java-archive", "application/java-archive", "application/x-python-code", "text/x-python", "text/x-perl", "text/x-php", "application/x-powershell":
		return true
	}
	switch strings.ToLower(path.Ext(f.Name)) {
	case ".exe", ".dll", ".scr", ".elf", ".so", ".sh", ".ps1", ".bat", ".vbs", ".hta", ".jar", ".py", ".pl", ".php", ".jsp", ".msi", ".bin":
		return true
	}
	return false
}

// hostCompromised 判断主机侧的命中是否说明主机已经失陷。
func hostCompromised(h *model.Hit) bool {
	switch h.Category {
	case detect.CatHostExec, detect.CatRevShell, detect.CatCredTheft, CatPayload:
		return h.Severity >= model.SevHigh
	case detect.CatSuspCmd, CatMalFile:
		return h.Severity >= model.SevCritical
	}
	return false
}
