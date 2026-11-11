package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netsa/internal/backup"
	"netsa/internal/block"
	"netsa/internal/detect"
	"netsa/internal/rulemgr"
)

func (s *Server) user(r *http.Request) string {
	if sess := sessionOf(r); sess != nil {
		return sess.User
	}
	return "anonymous"
}

func (s *Server) engine() *detect.Engine {
	if s.Pipeline != nil {
		if e := s.Pipeline.CurrentEngine(); e != nil {
			return e
		}
	}
	return s.Engine
}

// ---------------- 规则运营 ----------------

func (s *Server) rulesManaged(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeJSON(w, map[string]any{"rules": []any{}, "packs": []any{}})
		return
	}
	rules, packs := s.Rules.List()
	writeJSON(w, map[string]any{"rules": rules, "packs": packs, "shadow": s.Rules.Shadow()})
}

func (s *Server) rulesUpsert(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeError(w, http.StatusNotFound, "规则管理未启用")
		return
	}
	var rule detect.Rule
	if !decodeForm(w, r, &rule) {
		return
	}
	it, err := s.Rules.Upsert(rule, "", s.user(r))
	s.audit(r, "保存自定义规则", rule.ID, err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, it)
}

func (s *Server) rulesDelete(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeError(w, http.StatusNotFound, "规则管理未启用")
		return
	}
	id := r.PathValue("id")
	err := s.Rules.Delete(id)
	s.audit(r, "删除自定义规则", id, err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// rulesTest 用样本试运行一条规则，不保存。
func (s *Server) rulesTest(w http.ResponseWriter, r *http.Request) {
	var f struct {
		detect.Rule
		Sample string `json:"sample"`
	}
	if !decodeForm(w, r, &f) {
		return
	}
	res, err := rulemgr.Test(f.Rule, f.Sample)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, res)
}

func (s *Server) rulesPackInstall(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeError(w, http.StatusNotFound, "规则管理未启用")
		return
	}
	var p rulemgr.Pack
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "规则包格式错误")
		return
	}
	st, err := s.Rules.InstallPack(p, s.user(r))
	s.audit(r, "安装规则包", p.Name+" #"+strconv.FormatInt(p.Serial, 10), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, st)
}

func (s *Server) rulesPackDelete(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeError(w, http.StatusNotFound, "规则管理未启用")
		return
	}
	name := r.PathValue("name")
	err := s.Rules.UninstallPack(name)
	s.audit(r, "卸载规则包", name, err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// rulesSigma 转换 Sigma 规则。apply 为 false 时只预览，让管理员先看哪些规则被跳过以及原因。
func (s *Server) rulesSigma(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeError(w, http.StatusNotFound, "规则管理未启用")
		return
	}
	var f struct {
		YAML   string `json:"yaml"`
		Apply  bool   `json:"apply"`
		Shadow bool   `json:"shadow"` // 导入的规则先影子运行
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&f); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	res, err := rulemgr.ConvertSigma([]byte(f.YAML))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	applied := 0
	if f.Shadow {
		for i := range res.Rules {
			res.Rules[i].Shadow = true
		}
	}
	if f.Apply && len(res.Rules) > 0 {
		applied, err = s.Rules.ImportRules(res.Rules, "sigma", s.user(r))
		s.audit(r, "导入 Sigma 规则", strconv.Itoa(len(res.Rules))+" 条", err)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	writeJSON(w, map[string]any{"rules": res.Rules, "skipped": res.Skipped, "applied": applied})
}

// ---------------- 联动封禁 ----------------

func blockStatus(err error) int {
	var pe *block.ProtectedError
	switch {
	case errors.Is(err, block.ErrDisabled), errors.Is(err, block.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, block.ErrSelf):
		return http.StatusForbidden
	case errors.Is(err, block.ErrState):
		return http.StatusConflict
	case errors.As(err, &pe):
		return http.StatusBadRequest
	}
	return http.StatusBadRequest
}

func (s *Server) blockList(w http.ResponseWriter, r *http.Request) {
	pending, active := s.Block.Counts()
	items := s.Block.List(200)
	if items == nil {
		items = []block.Item{}
	}
	writeJSON(w, map[string]any{"enabled": s.Block != nil, "items": items, "pending": pending, "active": active, "webhook_failed": s.Block.WebhookFailed()})
}

func (s *Server) blockRequest(w http.ResponseWriter, r *http.Request) {
	var f struct {
		IP         string  `json:"ip"`
		Reason     string  `json:"reason"`
		TTLHours   float64 `json:"ttl_hours"`
		IncidentID uint64  `json:"incident_id"`
	}
	if !decodeForm(w, r, &f) {
		return
	}
	it, err := s.Block.Request(f.IP, f.Reason, time.Duration(f.TTLHours*float64(time.Hour)), f.IncidentID, s.user(r))
	if err != nil {
		writeError(w, blockStatus(err), err.Error())
		return
	}
	writeJSON(w, it)
}

func (s *Server) blockAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, block.ErrNotFound.Error())
		return
	}
	var f struct {
		Note string `json:"note"`
	}
	if r.ContentLength > 0 && !decodeForm(w, r, &f) {
		return
	}
	var it *block.Item
	switch r.PathValue("action") {
	case "approve":
		it, err = s.Block.Approve(id, s.user(r))
	case "reject":
		it, err = s.Block.Reject(id, s.user(r), f.Note)
	case "release":
		it, err = s.Block.Release(id, s.user(r), f.Note)
	default:
		writeError(w, http.StatusNotFound, "未知操作")
		return
	}
	if err != nil {
		writeError(w, blockStatus(err), err.Error())
		return
	}
	writeJSON(w, it)
}

// blockEDL 输出生效中的封禁地址（每行一个），供防火墙的外部动态列表定时拉取。用只读 API 令牌访问。
func (s *Server) blockEDL(w http.ResponseWriter, r *http.Request) {
	if s.Block == nil {
		writeError(w, http.StatusNotFound, block.ErrDisabled.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, strings.Join(s.Block.Active(), "\n"))
	io.WriteString(w, "\n")
}

// ---------------- 对接状态与备份 ----------------

// integrations 返回外部系统的对接状态，方便在页面上确认配置是否生效。
func (s *Server) integrations(w http.ResponseWriter, r *http.Request) {
	runs, dropped := s.Playbooks.Stats()
	res := map[string]any{
		"forward":   s.Forward.Stats(),
		"playbooks": map[string]any{"enabled": s.Playbooks != nil, "runs": runs, "dropped": dropped, "count": len(s.Cfg.Playbooks), "tickets": len(s.Cfg.Tickets)},
		"sso":       map[string]any{"ldap": s.Cfg.Server.LDAP.URL != "", "oidc": s.OIDC != nil},
		"backup":    map[string]any{"dir": s.Cfg.Storage.BackupDir != "", "supported": s.StateDir != ""},
	}
	if s.Intel != nil {
		res["intel"] = s.Intel.FeedStatuses()
	}
	writeJSON(w, res)
}

// adminBackup 下载状态备份（管理员）。内容包含密码哈希和模型密钥，下载行为写入审计。
func (s *Server) adminBackup(w http.ResponseWriter, r *http.Request) {
	if s.StateDir == "" {
		writeError(w, http.StatusNotFound, "没有配置状态目录（storage.snapshot），无法备份")
		return
	}
	extendDeadline(w, 30*time.Minute)
	if r.URL.Query().Get("standby") == "1" {
		// 备机每分钟同步一次：每个账号每小时只记一条审计，否则审计链被同步记录淹没
		s.standbyPull.Store(time.Now().Unix())
		key := s.user(r) + "|" + s.clientIP(r)
		s.standbyMu.Lock()
		if s.standbyAudit == nil {
			s.standbyAudit = map[string]time.Time{}
		}
		due := time.Since(s.standbyAudit[key]) >= time.Hour
		if due {
			s.standbyAudit[key] = time.Now()
		}
		s.standbyMu.Unlock()
		if due {
			s.audit(r, "备机同步状态", "每小时记录一次", nil)
		}
	} else {
		s.audit(r, "下载状态备份", "", nil)
	}
	// 先把内存中的最新状态写盘：快照每分钟才保存一次，备机同步与手动备份拿到的应是当前状态，而不是上一次定时保存的
	// （没有变化时保存几乎不花时间；与定时保存互斥）
	if snap := s.Cfg.Storage.Snapshot; snap != "" {
		if err := s.Store.Save(snap); err != nil {
			log.Printf("[backup] 备份前保存快照失败: %v", err)
		}
	}
	if err := s.Learn.Save(); err != nil {
		log.Printf("[backup] 备份前保存学习状态失败: %v", err)
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, backup.ScheduledName(time.Now())))
	w.Header().Set("Cache-Control", "no-store")
	if _, err := backup.Create(w, s.StateDir, backup.Options{Version: s.Version}); err != nil {
		// 响应头已发送，只能中断连接让下载失败，不能让客户拿到一个不完整却看似成功的备份
		panic(http.ErrAbortHandler)
	}
}
