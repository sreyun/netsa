package intel

import (
	"net/netip"
	"net/url"
	"strings"
)

// 域名情报：情报源中的恶意域名（C2、恶意软件投递、钓鱼、矿池），与 DNS 日志中内网主机的查询比对。
//
// 防误报：情报源常把被滥用的公共平台本身列进来（raw.githubusercontent.com、网盘、CDN），按域名匹配时
// 所有访问 GitHub、网盘的主机都会被当成失陷。下列条目一律丢弃，页面显示丢弃数量：
//   - 公共平台本身与其基础设施子域名（平台上属于个人的子域名，如 xxx.github.io、xxx.workers.dev 照常生效）；
//   - 只有一级、内网专用后缀（.local、.lan、.internal……）、公共后缀本身（com.cn、co.uk）；
//   - 配置的本单位域名（intel.domain_allowlist）。

const maxDomainLen = 253

// infraRoots 是整个域名下都是平台基础设施的公共服务：情报条目等于或位于其下都丢弃。
var infraRoots = domainSet("githubusercontent.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "discordapp.com",
	"discordapp.net", "dropboxusercontent.com", "cloudfront.net", "akamaized.net", "akamaihd.net", "edgekey.net", "edgesuite.net",
	"fastly.net", "azureedge.net", "msedge.net", "jsdelivr.net", "unpkg.com", "cdn.cloudflare.net", "alicdn.com", "bdstatic.com",
	"qpic.cn", "gtimg.cn", "myqcloud.com", "aliyuncs.com", "bcebos.com", "myhuaweicloud.com")

// sharedHosts 是被滥用托管恶意内容、但本身大量用于正常业务的平台主机名：条目等于它（或 www. 加它）时丢弃。
var sharedHosts = domainSet("github.com", "gitlab.com", "bitbucket.org", "gitee.com", "github.io", "google.com", "drive.google.com",
	"docs.google.com", "sites.google.com", "storage.googleapis.com", "dropbox.com", "onedrive.live.com", "1drv.ms", "mediafire.com",
	"mega.nz", "pastebin.com", "paste.ee", "telegram.org", "t.me", "discord.com", "microsoft.com", "live.com", "office.com",
	"sharepoint.com", "windows.net", "blob.core.windows.net", "amazonaws.com", "s3.amazonaws.com", "cloudflare.com",
	"workers.dev", "pages.dev", "r2.dev", "netlify.app", "vercel.app", "herokuapp.com", "firebaseapp.com", "web.app", "appspot.com",
	"blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "ngrok.io", "ngrok-free.app", "baidu.com", "pan.baidu.com",
	"qq.com", "weixin.qq.com", "aliyun.com", "huaweicloud.com", "163.com", "126.com", "sina.com.cn", "apple.com", "icloud.com",
	"yahoo.com", "bing.com", "yandex.ru", "twitter.com", "x.com", "facebook.com", "youtube.com", "linkedin.com", "dingtalk.com",
	"feishu.cn", "weibo.com", "jianshu.com", "csdn.net", "zhihu.com", "lanzoui.com", "lanzous.com", "lanzoux.com")

// 内网专用的顶级域名。
var privateTLDs = domainSet("local", "lan", "internal", "intranet", "corp", "home", "localhost", "localdomain", "arpa", "invalid")

// 多级公共后缀本身：只写了后缀的条目没有意义。
var publicSuffixes = domainSet("com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "co.uk", "org.uk", "ac.uk", "gov.uk",
	"com.au", "net.au", "co.jp", "ne.jp", "or.jp", "com.hk", "com.tw", "com.sg", "co.kr", "com.br", "co.in", "co.za", "com.mx", "com.ru")

func domainSet(list ...string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, d := range list {
		m[d] = true
	}
	return m
}

// within 判断 name 是否等于或位于集合中的某个域名之下。
func within(name string, set map[string]bool) bool {
	for d := name; d != ""; {
		if set[d] {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return false
}

// normDomain 归一情报中的域名，不可用（格式不对、公共平台、内网后缀）时返回空串。
func normDomain(v string, allow map[string]bool) string {
	d := strings.ToLower(strings.TrimSpace(v))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	if d == "" || len(d) > maxDomainLen || !strings.Contains(d, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return ""
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ""
			}
		}
	}
	tld := d[strings.LastIndexByte(d, '.')+1:]
	if privateTLDs[tld] || publicSuffixes[d] || within(d, infraRoots) || sharedHosts[d] || sharedHosts[strings.TrimPrefix(d, "www.")] || within(d, allow) {
		return ""
	}
	return d
}

// urlHost 取出 URL 中的主机名，不是 URL 时返回空串。
func urlHost(v string) string {
	if !strings.Contains(v, "://") {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// hasDomain 判断域名或其任一上级域名是否在列表中（情报标记了 evil.example，a.evil.example 同样命中；反之不成立）。
func (l *list) hasDomain(name string) bool {
	if len(l.domains) == 0 {
		return false
	}
	for d := name; strings.Contains(d, "."); {
		if _, ok := l.domains[d]; ok {
			return true
		}
		d = d[strings.IndexByte(d, '.')+1:]
	}
	return false
}

// MatchDomain 返回标记了该域名（或其上级域名）的情报名称。
func (db *DB) MatchDomain(name string) []string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || !strings.Contains(name, ".") {
		return nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	var hits []string
	for _, l := range db.lists {
		if l.hasDomain(name) {
			hits = append(hits, l.name)
		}
	}
	return hits
}
