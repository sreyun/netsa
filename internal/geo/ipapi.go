package geo

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// IPAPI 调用 ip-api.com 兼容的批量接口进行在线定位（每批最多 100 个 IP）。
// 免费接口限制为每分钟 15 次批量请求，这里根据响应头 X-Rl / X-Ttl 自动限速。
type IPAPI struct {
	URL    string
	Lang   string
	client *http.Client
}

func NewIPAPI(url, lang string) *IPAPI {
	return &IPAPI{URL: url, Lang: lang, client: &http.Client{Timeout: 15 * time.Second}}
}

func (*IPAPI) Name() string { return "ip-api" }

type ipapiResp struct {
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Query       string  `json:"query"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	District    string  `json:"district"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	ASName      string  `json:"asname"`
	Reverse     string  `json:"reverse"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
}

const ipapiFields = "status,message,query,country,countryCode,regionName,city,district,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"

// run 攒批查询；done 对每一批调用一次，err 非空表示整批失败（可重试）。
func (a *IPAPI) run(ctx context.Context, q <-chan string, done func(res map[string]*SourceResult, batch []string, err error)) {
	for {
		var batch []string
		select {
		case <-ctx.Done():
			return
		case ip := <-q:
			batch = append(batch, ip)
		}
		// 攒批：最多等 3 秒或 100 个
		timer := time.NewTimer(3 * time.Second)
	collect:
		for len(batch) < 100 {
			select {
			case ip := <-q:
				batch = append(batch, ip)
			case <-timer.C:
				break collect
			case <-ctx.Done():
				timer.Stop()
				return
			}
		}
		timer.Stop()
		res, wait, err := a.query(ctx, batch)
		if err != nil {
			log.Printf("[geo] 在线定位失败(%d 个IP): %v", len(batch), err)
		}
		done(res, batch, err)
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
		}
	}
}

func (a *IPAPI) query(ctx context.Context, ips []string) (map[string]*SourceResult, time.Duration, error) {
	body, _ := json.Marshal(ips)
	url := a.URL
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	url += sep + "fields=" + ipapiFields + "&lang=" + a.Lang
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 10 * time.Second, err
	}
	defer resp.Body.Close()
	wait := 4 * time.Second // 15 次/分钟
	if rl, _ := strconv.Atoi(resp.Header.Get("X-Rl")); resp.Header.Get("X-Rl") != "" && rl <= 0 {
		if ttl, err := strconv.Atoi(resp.Header.Get("X-Ttl")); err == nil {
			wait = time.Duration(ttl+1) * time.Second
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, time.Minute, errStatus(resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, wait, errStatus(resp.StatusCode)
	}
	var list []ipapiResp
	// 第三方接口（或配置的兼容服务）的响应大小加上限：100 个 IP 的结果约 30KB
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list); err != nil {
		return nil, wait, err
	}
	out := map[string]*SourceResult{}
	for _, r := range list {
		if r.Status != "success" {
			continue
		}
		sr := &SourceResult{
			Source: "ip-api", Country: r.Country, CountryCode: r.CountryCode, Province: r.RegionName,
			City: r.City, District: r.District, Lat: r.Lat, Lon: r.Lon, Timezone: r.Timezone,
			ISP: r.ISP, ASOrg: r.ASName, RDNS: r.Reverse, Mobile: r.Mobile, Proxy: r.Proxy, Hosting: r.Hosting,
		}
		if sr.ASOrg == "" {
			sr.ASOrg = r.Org
		}
		// as 字段形如 "AS4134 CHINANET-BACKBONE"
		if f := strings.Fields(r.AS); len(f) > 0 && strings.HasPrefix(f[0], "AS") {
			n, _ := strconv.ParseUint(f[0][2:], 10, 32)
			sr.ASN = uint(n)
		}
		out[r.Query] = sr
	}
	return out, wait, nil
}

type errStatus int

func (e errStatus) Error() string { return "HTTP " + strconv.Itoa(int(e)) }
