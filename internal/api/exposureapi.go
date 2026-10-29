package api

import (
	"net/http"

	"netsa/internal/config"
	"netsa/internal/exposure"
	"netsa/internal/pipeline"
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
		// 按会话证据（安全域、DNAT 后地址、应答包数）判断放行的探测是否到达服务
		"reach_check": s.Exposure.ReachCheck(),
		"unreached":   s.Exposure.Unreached(),
		"policies":    topPolicies(s.Exposure.Policies(), 50),
		"learned":     learnedList(s.Exposure.Learned()),
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

// topPolicies 返回放行次数最多的 n 条可疑放行策略（外部流量被放行但未到达任何服务）。
func topPolicies(list []exposure.PolicyNote, n int) []exposure.PolicyNote {
	if list == nil {
		return []exposure.PolicyNote{}
	}
	if len(list) > n {
		list = list[:n]
	}
	return list
}

// learnedList 返回根据会话证据自动识别的对外服务（最多 500 条）。
func learnedList(list []exposure.LearnedService) []exposure.LearnedService {
	if list == nil {
		return []exposure.LearnedService{}
	}
	if len(list) > 500 {
		list = list[:500]
	}
	return list
}

// proxyPeers 返回自动识别的反向代理（内网，已自动信任）与疑似未配置的 CDN / 代理节点（公网，需人工确认）。
func (s *Server) proxyPeers() []pipeline.ProxyPeer {
	if s.Pipeline == nil || s.Pipeline.RealIP == nil {
		return []pipeline.ProxyPeer{}
	}
	return s.Pipeline.RealIP.Proxies()
}
