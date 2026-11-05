package api

import (
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"netsa/internal/store"
)

// chainList 返回资产攻击链路列表。参数：q 资产名称 / 域名 / 地址关键字；stage 至少推进到该阶段之后
// （如 exploit 表示越过侦察）；compromised=1 只看研判为失陷的；limit 最多返回的条数（默认 100，最多 500）。
func (s *Server) chainList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cq := store.ChainQuery{Search: strings.TrimSpace(q.Get("q")), Stage: q.Get("stage"), Compromised: q.Get("compromised") == "1"}
	if utf8.RuneCountInString(cq.Search) > 100 {
		writeError(w, http.StatusBadRequest, "关键字过长")
		return
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit 无效")
			return
		}
		cq.Limit = n
	}
	writeJSON(w, s.Store.ChainList(cq))
}

// chainDetail 返回一个资产的完整攻击链路。asset 可以是台账资产名称、站点域名或主机地址。
func (s *Server) chainDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("asset"))
	if id == "" || utf8.RuneCountInString(id) > 300 {
		writeError(w, http.StatusBadRequest, "请指定资产")
		return
	}
	c := s.Store.AssetChain(id)
	if c == nil {
		writeError(w, http.StatusNotFound, "没有该资产的攻击记录")
		return
	}
	writeJSON(w, c)
}
