package api

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"netsa/internal/config"
	"netsa/internal/store"
)

// visibility 汇总评估“日志与检测覆盖”所需的部署信息。
func (s *Server) visibility(r *http.Request) store.Visibility {
	v := store.Visibility{ParseRate: 1, Archive: s.Archive != nil, AuthEnabled: s.Auth != nil,
		Intel:         len(s.Cfg.Intel.Blocklists),
		HTTPS:         s.Cfg.Server.TLSCert != "" || r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		AllowNetworks: len(s.Cfg.Server.AllowNetworks) > 0,
	}
	if s.Cfg.Intel.TorExitURL != "" {
		v.Intel++
	}
	var parsed, failed int64
	for _, st := range s.Ingest.Stats() {
		parsed += st.Parsed
		failed += st.Failed
	}
	if parsed+failed > 0 {
		v.ParseRate = float64(parsed) / float64(parsed+failed)
	}
	names := s.Geo.ProviderNames()
	v.PreciseGeo = slices.Contains(names, "maxmind") || slices.Contains(names, "ip-api")
	for _, rb := range s.Notifier.Info().Robots {
		if rb.Enabled {
			v.Robots++
		}
	}
	return v
}

// assessment 返回安全防护评估：七个维度的评分、总评、处置建议、疑似失陷资产与 ATT&CK 矩阵。
func (s *Server) assessment(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.Assess(s.visibility(r)))
}

// allowNetworks 限制访问大屏与 API 的来源网段（server.allow_networks）。本机回环地址始终允许，便于本机运维与健康检查。
func (s *Server) allowNetworks(next http.Handler) http.Handler {
	var nets []netip.Prefix
	for _, n := range s.Cfg.Server.AllowNetworks {
		if p, err := config.ParseNetwork(n); err == nil {
			nets = append(nets, p)
		}
	}
	if len(nets) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		if h, _, err := net.SplitHostPort(ip); err == nil {
			ip = h
		}
		if a, err := netip.ParseAddr(ip); err == nil {
			a = a.Unmap()
			if a.IsLoopback() {
				next.ServeHTTP(w, r)
				return
			}
			for _, p := range nets {
				if p.Contains(a) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		writeErrorCode(w, http.StatusForbidden, "当前来源地址不在允许访问的网段内（server.allow_networks）", "forbidden_network")
	})
}
