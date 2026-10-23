package geo

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RDAPInfo 是 IP 归属网络的注册信息（WHOIS 的结构化替代），用于确认网段所有者与滥用投诉渠道。
type RDAPInfo struct {
	IP          string    `json:"ip"`
	Handle      string    `json:"handle"`
	Name        string    `json:"name"`
	Range       string    `json:"range"`
	CIDR        []string  `json:"cidr"`
	Country     string    `json:"country"`
	Type        string    `json:"type"`
	Org         string    `json:"org"`
	AbuseEmail  []string  `json:"abuse_email"`
	Description []string  `json:"description"`
	Registered  string    `json:"registered"`
	Updated     string    `json:"updated"`
	Source      string    `json:"source"`
	QueriedAt   time.Time `json:"queried_at"`
}

// RDAPClient 通过 rdap.org 引导服务查询各 RIR（APNIC/ARIN/RIPE...）。
type RDAPClient struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]*RDAPInfo
}

func NewRDAPClient() *RDAPClient {
	// 部分 RIR（如 APNIC）的 RDAP 服务在 HTTP/2 下会直接断开连接，这里强制使用 HTTP/1.1
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{NextProtos: []string{"http/1.1"}},
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        10,
	}
	return &RDAPClient{client: &http.Client{Timeout: 15 * time.Second, Transport: tr}, cache: map[string]*RDAPInfo{}}
}

type rdapEntity struct {
	Roles    []string        `json:"roles"`
	VCard    json.RawMessage `json:"vcardArray"`
	Entities []rdapEntity    `json:"entities"`
	Handle   string          `json:"handle"`
}

type rdapResp struct {
	Handle       string `json:"handle"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Country      string `json:"country"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Port43       string `json:"port43"`
	CIDRs        []struct {
		V4 string `json:"v4prefix"`
		V6 string `json:"v6prefix"`
		L  int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Remarks []struct {
		Description []string `json:"description"`
	} `json:"remarks"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []rdapEntity `json:"entities"`
}

func (c *RDAPClient) Lookup(ctx context.Context, ip string) (*RDAPInfo, error) {
	c.mu.Lock()
	if v, ok := c.cache[ip]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/ip/"+ip, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "netsa-rdap/1.0")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP 返回 HTTP %d", resp.StatusCode)
	}
	var r rdapResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	info := &RDAPInfo{
		IP: ip, Handle: r.Handle, Name: r.Name, Type: r.Type, Country: r.Country,
		Range: r.StartAddress + " - " + r.EndAddress, Source: r.Port43, QueriedAt: time.Now(),
	}
	if info.Source == "" {
		info.Source = resp.Request.URL.Host
	}
	for _, cidr := range r.CIDRs {
		p := cidr.V4
		if p == "" {
			p = cidr.V6
		}
		info.CIDR = append(info.CIDR, p+"/"+strconv.Itoa(cidr.L))
	}
	for _, rm := range r.Remarks {
		info.Description = append(info.Description, rm.Description...)
	}
	for _, ev := range r.Events {
		switch ev.Action {
		case "registration":
			info.Registered = ev.Date
		case "last changed":
			info.Updated = ev.Date
		}
	}
	var walk func([]rdapEntity)
	walk = func(es []rdapEntity) {
		for _, e := range es {
			fn, emails := parseVCard(e.VCard)
			for _, role := range e.Roles {
				switch role {
				case "abuse":
					info.AbuseEmail = appendUniq(info.AbuseEmail, emails...)
				case "registrant", "administrative":
					if info.Org == "" && fn != "" {
						info.Org = fn
					}
				}
			}
			walk(e.Entities)
		}
	}
	walk(r.Entities)

	c.mu.Lock()
	if len(c.cache) > 5000 {
		c.cache = map[string]*RDAPInfo{}
	}
	c.cache[ip] = info
	c.mu.Unlock()
	return info, nil
}

// parseVCard 解析 jCard：["vcard", [["fn", {}, "text", "Name"], ["email", {}, "text", "a@b"]]]
func parseVCard(raw json.RawMessage) (fn string, emails []string) {
	if len(raw) == 0 {
		return
	}
	var v []any
	if json.Unmarshal(raw, &v) != nil || len(v) < 2 {
		return
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		arr, _ := p.([]any)
		if len(arr) < 4 {
			continue
		}
		key, _ := arr[0].(string)
		val, _ := arr[3].(string)
		switch key {
		case "fn":
			fn = val
		case "email":
			emails = append(emails, strings.TrimSpace(val))
		}
	}
	return
}

func appendUniq(list []string, items ...string) []string {
	for _, it := range items {
		dup := false
		for _, l := range list {
			if l == it {
				dup = true
				break
			}
		}
		if !dup && it != "" {
			list = append(list, it)
		}
	}
	return list
}
