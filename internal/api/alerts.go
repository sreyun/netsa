package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"netsa/internal/alert"
)

// robotForm 是界面提交的机器人表单。编辑时 url / secret 留空表示保持原值。
type robotForm struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	URL         string   `json:"url"`
	Secret      string   `json:"secret"`
	ClearSecret bool     `json:"clear_secret"`
	Levels      []string `json:"levels"`
	Enabled     bool     `json:"enabled"`
	Report      bool     `json:"report"`
}

func (f robotForm) robot() alert.Robot {
	return alert.Robot{Name: f.Name, Type: f.Type, URL: f.URL, Secret: f.Secret, Levels: f.Levels, Enabled: f.Enabled, Report: f.Report}
}

func decodeForm(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "请求体必须为 JSON")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return false
	}
	return true
}

func (s *Server) alertError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, alert.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, alert.ErrReadOnly):
		writeError(w, http.StatusForbidden, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func (s *Server) alertInfo(w http.ResponseWriter, r *http.Request) {
	info := s.Notifier.Info()
	info.ReportTime = s.Cfg.Alert.ReportTime
	writeJSON(w, info)
}

func (s *Server) robotCreate(w http.ResponseWriter, r *http.Request) {
	var f robotForm
	if !decodeForm(w, r, &f) {
		return
	}
	v, err := s.Notifier.Create(f.robot())
	s.audit(r, "添加告警机器人", f.Name+"（"+f.Type+"）", errIfNoID(v, err))
	if err != nil && v.ID == "" {
		s.alertError(w, err)
		return
	}
	writeJSON(w, map[string]any{"robot": v, "warning": errText(err)})
}

func (s *Server) robotUpdate(w http.ResponseWriter, r *http.Request) {
	var f robotForm
	if !decodeForm(w, r, &f) {
		return
	}
	v, err := s.Notifier.Update(r.PathValue("id"), f.robot(), f.ClearSecret)
	s.audit(r, "修改告警机器人", f.Name, errIfNoID(v, err))
	if err != nil && v.ID == "" {
		s.alertError(w, err)
		return
	}
	writeJSON(w, map[string]any{"robot": v, "warning": errText(err)})
}

func (s *Server) robotDelete(w http.ResponseWriter, r *http.Request) {
	err := s.Notifier.Delete(r.PathValue("id"))
	s.audit(r, "删除告警机器人", r.PathValue("id"), err)
	if err != nil && !strings.HasPrefix(err.Error(), "保存") {
		s.alertError(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// robotTest 发送测试消息。路径中带 id 时测试已保存的机器人（表单中未填写的地址与密钥沿用已保存的值）。
func (s *Server) robotTest(w http.ResponseWriter, r *http.Request) {
	var f robotForm
	if r.ContentLength != 0 && !decodeForm(w, r, &f) {
		return
	}
	err := s.Notifier.Test(r.Context(), r.PathValue("id"), f.robot())
	s.audit(r, "发送测试消息", f.Name, err)
	if errors.Is(err, alert.ErrNotFound) {
		s.alertError(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": err == nil, "error": errText(err)})
}

// errIfNoID 返回操作是否失败：保存文件失败但配置已生效（返回了机器人）时视为成功。
func errIfNoID(v alert.RobotView, err error) error {
	if v.ID != "" {
		return nil
	}
	return err
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// sameOrigin 拒绝跨站提交的写请求（CSRF）：浏览器跨站请求会带上 Origin，且与本站 Host 不一致。
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || !strings.EqualFold(u.Host, r.Host) {
					writeError(w, http.StatusForbidden, "拒绝跨站请求")
					return
				}
			}
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				writeError(w, http.StatusForbidden, "拒绝跨站请求")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
