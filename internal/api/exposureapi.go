package api

import (
	"net/http"

	"netsa/internal/config"
	"netsa/internal/exposure"
)

// exposureInfo 返回对外发布服务清单（DNAT 映射）与过滤统计。
// 开启后，目标为公网、端口未列入清单的端口探测与端口级暴力破解只打标签、不产生告警。
func (s *Server) exposureInfo(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"enabled":       false,
		"mappings":      []config.ExposureService{},
		"muted":         int64(0),
		"intranet":      []string{},
		"allowed_ports": []int{},
		"candidates":    []exposure.Candidate{},
	}
	if s.Exposure != nil {
		resp["enabled"] = s.Exposure.Enforcing()
		if list := s.Exposure.List(); len(list) > 0 {
			resp["mappings"] = list
		}
		resp["muted"] = s.Exposure.Muted()
		if c := s.Exposure.Candidates(); len(c) > 0 {
			resp["candidates"] = c
		}
	}
	if s.Cfg != nil {
		if len(s.Cfg.Exposure.AllowedPorts) > 0 {
			resp["allowed_ports"] = s.Cfg.Exposure.AllowedPorts
		}
		if len(s.Cfg.Geo.Intranet) > 0 {
			resp["intranet"] = s.Cfg.Geo.Intranet
		}
	}
	writeJSON(w, resp)
}
