package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netsa/internal/archive"
	"netsa/internal/geo"
	"netsa/internal/rawlog"
	"netsa/internal/store"
)

// 一键取证包（P2-4）：把一个安全事件的证据打包成 zip，用于移交、报案、复盘留档。
//
//	README.txt        包内文件说明与校验方法
//	incident.json     事件详情：等级、状态、处置记录、告警、命中规则、目标
//	timeline.csv      时间线：告警与处置记录按时间排列
//	source.json       来源的画像：归属地、威胁评分、命中规则、同源关联
//	chains.json       涉及资产的攻击链路（侦察 → 利用 → 突破 → 控制 → 横向 → 窃取）
//	alerts-archive.csv 归档库中该来源在事件期间的全部告警（启用告警归档时）
//	rawlog.log        事件期间该来源的原始日志（启用原始日志留存时，最多 5000 条）
//	manifest.json     生成时间、操作人、版本、每个文件的大小与 SHA-256
//	SHA256SUMS        sha256sum -c 可直接校验的哈希清单

const (
	evidenceRawMax     = 5000
	evidenceArchiveMax = 5000
	evidenceMargin     = 10 * time.Minute // 原始日志与归档告警在事件时间范围前后多取的时间
)

type evidenceFile struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Note   string `json:"note,omitempty"`
	data   []byte
}

type evidenceManifest struct {
	Incident    uint64         `json:"incident"`
	Source      string         `json:"source"`
	GeneratedAt time.Time      `json:"generated_at"`
	GeneratedBy string         `json:"generated_by"`
	Version     string         `json:"version"`
	From        time.Time      `json:"from"`
	To          time.Time      `json:"to"`
	Files       []evidenceFile `json:"files"`
	Notes       []string       `json:"notes,omitempty"` // 没有包含的内容及原因
}

// incidentEvidence 导出事件的取证包（运营分析员以上：包含原始日志）。
func (s *Server) incidentEvidence(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	d := s.Store.Incident(id)
	if d == nil {
		writeError(w, http.StatusNotFound, store.ErrNoIncident.Error())
		return
	}
	extendDeadline(w, 2*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	from, to := d.FirstSeen.Add(-evidenceMargin), d.LastSeen.Add(evidenceMargin)
	if to.Sub(from) > 31*24*time.Hour { // 原始日志检索的范围上限
		from = to.Add(-31 * 24 * time.Hour)
	}
	m := evidenceManifest{Incident: id, Source: d.Key, GeneratedAt: s.now(), GeneratedBy: user, Version: s.Version, From: from, To: to}
	var files []evidenceFile
	add := func(name string, data []byte, note string) {
		sum := sha256.Sum256(data)
		files = append(files, evidenceFile{Name: name, Size: len(data), SHA256: hex.EncodeToString(sum[:]), Note: note, data: data})
	}
	addJSON := func(name string, v any, note string) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			b = []byte(`{"error":` + strconv.Quote(err.Error()) + `}`)
		}
		add(name, b, note)
	}
	addJSON("incident.json", d, "事件详情、处置记录与内存中保留的告警（最近 200 条）")
	add("timeline.csv", evidenceTimeline(d, s.now().Location()), "告警与处置记录按时间排列")
	if p := s.Store.IPDetail(d.Key); p != nil {
		addJSON("source.json", p, "来源画像、命中规则与同源关联")
	}
	if chains := s.evidenceChains(d); len(chains) > 0 {
		addJSON("chains.json", chains, "涉及资产的攻击链路")
	}
	if s.Archive != nil {
		if b, n, err := s.evidenceArchive(ctx, d.Key, from, to); err != nil {
			m.Notes = append(m.Notes, "归档告警查询失败："+err.Error())
		} else {
			add("alerts-archive.csv", b, fmt.Sprintf("归档库中该来源在事件期间的告警，共 %d 条", n))
		}
	} else {
		m.Notes = append(m.Notes, "未启用告警归档：只包含内存中保留的告警（incident.json）")
	}
	if s.RawLog != nil {
		q := rawlog.Query{From: from, To: to, IP: d.Key, Limit: evidenceRawMax}
		res, err := s.RawLog.Search(ctx, q)
		if err != nil {
			m.Notes = append(m.Notes, "原始日志检索失败："+err.Error())
		} else {
			var buf bytes.Buffer
			rawlog.Export(&buf, res.Records, s.now().Location())
			note := fmt.Sprintf("事件期间该来源的原始日志，共 %d 条", len(res.Records))
			if len(res.Records) >= evidenceRawMax {
				note += "（达到上限，更早的日志请在日志检索中导出）"
			}
			add("rawlog.log", buf.Bytes(), note)
		}
	} else {
		m.Notes = append(m.Notes, "未启用原始日志留存：不包含原始日志")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	m.Files = files
	man, _ := json.MarshalIndent(m, "", "  ")
	var sums strings.Builder
	for _, f := range files {
		fmt.Fprintf(&sums, "%s  %s\n", f.SHA256, f.Name)
	}
	manSum := sha256.Sum256(man)
	fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(manSum[:]), "manifest.json")
	readme := evidenceReadme(m)

	name := fmt.Sprintf("netsa-evidence-incident-%d-%s.zip", id, s.now().Format("20060102-150405"))
	s.audit(r, "导出取证包", fmt.Sprintf("事件 #%d（%s），%d 个文件", id, d.Key, len(files)), nil)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	zw := zip.NewWriter(w)
	write := func(name string, data []byte) {
		if fw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: m.GeneratedAt}); err == nil {
			fw.Write(data)
		}
	}
	write("README.txt", readme)
	for _, f := range files {
		write(f.Name, f.data)
	}
	write("manifest.json", man)
	write("SHA256SUMS", []byte(sums.String()))
	zw.Close()
}

// evidenceTimeline 生成时间线：告警与处置记录按时间排列。
func evidenceTimeline(d *store.IncidentDetail, loc *time.Location) []byte {
	type row struct {
		t   time.Time
		rec []string
	}
	var rows []row
	for _, a := range d.AlertList {
		rows = append(rows, row{a.Time, []string{a.Time.In(loc).Format("2006-01-02 15:04:05"), "告警", a.Severity.Label(), a.Name + "（" + a.RuleID + "）",
			a.Category, a.Result, a.Target, a.Evidence}})
	}
	for _, n := range d.Notes {
		text := n.Action
		if n.Text != "" {
			if text != "" {
				text += "；"
			}
			text += n.Text
		}
		rows = append(rows, row{n.Time, []string{n.Time.In(loc).Format("2006-01-02 15:04:05"), "处置记录", "", n.User, "", "", "", text}})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].t.Before(rows[j].t) })
	var buf bytes.Buffer
	buf.WriteString("\xef\xbb\xbf") // UTF-8 BOM：Excel 直接打开不乱码
	cw := csv.NewWriter(&buf)
	cw.Write([]string{"时间", "类型", "等级", "名称 / 操作人", "攻击类型", "研判结果", "目标", "证据 / 说明"})
	for _, r := range rows {
		cw.Write(csvSafe(r.rec)) // 证据中可能有以 = 开头的攻击载荷
	}
	cw.Flush()
	return buf.Bytes()
}

// evidenceChains 返回事件涉及资产的攻击链路：事件中的资产、目标站点 / 地址，来源为内网主机时也包括它自身。
func (s *Server) evidenceChains(d *store.IncidentDetail) []*store.AssetChain {
	var ids []string
	ids = append(ids, d.Assets...)
	for _, t := range d.Targets {
		h := t.Name
		if i := strings.IndexAny(h, " :/"); i > 0 {
			h = h[:i]
		}
		ids = append(ids, h)
	}
	if geo.IsPrivate(d.Key) {
		ids = append(ids, d.Key)
	}
	seen := map[string]bool{}
	var out []*store.AssetChain
	for _, id := range ids {
		if id == "" || id == "-" || len(out) >= 5 {
			continue
		}
		c := s.Store.AssetChain(id)
		if c == nil || seen[c.Key] {
			continue
		}
		seen[c.Key] = true
		out = append(out, c)
	}
	return out
}

// evidenceArchive 查询归档库中该来源在事件期间的告警，生成 CSV。
func (s *Server) evidenceArchive(ctx context.Context, ip string, from, to time.Time) ([]byte, int, error) {
	var buf bytes.Buffer
	buf.WriteString("\xef\xbb\xbf")
	cw := csv.NewWriter(&buf)
	cw.Write([]string{"时间", "告警编号", "来源", "归属地", "规则", "名称", "攻击类型", "等级", "阶段", "研判结果", "目标", "证据"})
	n := 0
	for offset := 0; n < evidenceArchiveMax; offset += 500 {
		res, err := s.Archive.Search(ctx, archive.Query{From: from, To: to, IP: ip, Limit: 500, Offset: offset})
		if err != nil {
			return nil, 0, err
		}
		for _, a := range res.Items {
			cw.Write(csvSafe([]string{a.Time.In(s.now().Location()).Format("2006-01-02 15:04:05"), strconv.FormatInt(a.AlertID, 10), a.SrcIP, a.Location,
				a.RuleID, a.Name, a.Category, a.Severity.Label(), a.Phase, a.Result, a.Target, a.Evidence}))
			n++
		}
		if !res.HasMore || len(res.Items) == 0 {
			break
		}
	}
	cw.Flush()
	return buf.Bytes(), n, nil
}

func evidenceReadme(m evidenceManifest) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "netsa 取证包 —— 安全事件 #%d（来源 %s）\r\n\r\n", m.Incident, m.Source)
	fmt.Fprintf(&b, "生成时间：%s\r\n操作人：%s\r\n版本：netsa %s\r\n事件时间范围（含前后 %s）：%s ~ %s\r\n\r\n", m.GeneratedAt.Format(time.RFC3339), m.GeneratedBy, m.Version,
		evidenceMargin, m.From.Format(time.RFC3339), m.To.Format(time.RFC3339))
	b.WriteString("包内文件：\r\n")
	for _, f := range m.Files {
		fmt.Fprintf(&b, "  %-20s %10d 字节  %s\r\n", f.Name, f.Size, f.Note)
	}
	b.WriteString("  manifest.json        生成信息与每个文件的大小、SHA-256\r\n  SHA256SUMS           哈希清单\r\n\r\n")
	if len(m.Notes) > 0 {
		b.WriteString("说明：\r\n")
		for _, n := range m.Notes {
			b.WriteString("  - " + n + "\r\n")
		}
		b.WriteString("\r\n")
	}
	b.WriteString("校验完整性：解压后在目录中执行 sha256sum -c SHA256SUMS（Windows 可用 certutil -hashfile 文件名 SHA256 逐个核对）。\r\n")
	b.WriteString("原始日志的防篡改校验：在“系统管理 → 原始日志完整性校验”中核对留存日志的哈希链。\r\n")
	return []byte(b.String())
}
