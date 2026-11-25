package demo

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// AI 使用的演示数据：办公终端（10.0.0.40 ~ 59）访问常见 AI 服务的 DNS 查询、TLS 握手（Zeek ssl.log）与防火墙会话日志
// （带上传 / 下载字节数，与握手的源端口不同，按“终端 + 目的地址”归属），以及几个不在目录中的疑似 AI 域名。
// 目的地址用 RFC 5737 文档地址 198.51.100.0/24，不与演示情报（203.0.113.0/24）重叠。
// 使用单独的随机数源：不改变其他演示数据的随机序列。

type aiSite struct {
	host string
	ip   string
	big  bool // 偶尔有大文件上传（文档、代码包）
}

var aiSites = []aiSite{
	{"chatgpt.com", "198.51.100.10", true}, {"api.openai.com", "198.51.100.11", false}, {"claude.ai", "198.51.100.12", true},
	{"chat.deepseek.com", "198.51.100.13", true}, {"api.deepseek.com", "198.51.100.14", false}, {"kimi.com", "198.51.100.15", true},
	{"www.doubao.com", "198.51.100.16", false}, {"api.githubcopilot.com", "198.51.100.17", false}, {"api2.cursor.sh", "198.51.100.18", false},
	{"huggingface.co", "198.51.100.19", false}, {"dashscope.aliyuncs.com", "198.51.100.20", false}, {"gemini.google.com", "198.51.100.21", false},
	{"yuanbao.tencent.com", "198.51.100.22", false}, {"tongyi.aliyun.com", "198.51.100.23", false},
}

// 不在目录中的疑似 AI 域名（.example 为保留的示例域名）
var aiCandidates = []string{"api.openai-relay.example", "chat.gptgod.example", "www.llm-gateway.example"}

// aiPrefs 是每个终端常用的服务（下标），让统计像真实的使用分布：多数人用一两个对话助手，开发人员用编程助手与模型接口。
func aiPrefs(client int) []int {
	switch client % 7 {
	case 0:
		return []int{3, 5}
	case 1:
		return []int{0, 3}
	case 2:
		return []int{7, 8, 4}
	case 3:
		return []int{2, 0, 9}
	case 4:
		return []int{6, 12}
	case 5:
		return []int{1, 10, 13}
	default:
		return []int{3, 11}
	}
}

func (s *Sim) aiRand() *rand.Rand {
	if s.ar == nil {
		s.ar = rand.New(rand.NewSource(20261124))
	}
	return s.ar
}

func (s *Sim) aiSSLLine(t time.Time, client string, sport int, site aiSite) string {
	r := s.aiRand()
	return strings.Join([]string{fmt.Sprintf("%.6f", float64(t.UnixNano())/1e9), fmt.Sprintf("C%08x", r.Uint32()), client, fmt.Sprint(sport),
		site.ip, "443", "TLSv13", "TLS_AES_128_GCM_SHA256", "x25519", site.host, "F", "-", "h2", "T", "CsiI", "-", "-", "T"}, "\t")
}

// aiTraffic 生成一分钟内的 AI 使用日志。
func (s *Sim) aiTraffic(w *writer, t time.Time, intensity int) {
	r := s.aiRand()
	if h := t.Hour(); h < 8 || h > 21 { // 夜间很少有人使用
		if r.Intn(4) != 0 {
			return
		}
	}
	for i := 0; i < intensity; i++ {
		c := 40 + r.Intn(20)
		client := fmt.Sprintf("10.0.0.%d", c)
		prefs := aiPrefs(c)
		site := aiSites[prefs[r.Intn(len(prefs))]]
		at := t.Add(time.Duration(r.Intn(60)) * time.Second)
		fmt.Fprintln(w.dns, s.dnsLine(at, client, site.host, "A", "NOERROR"))
		sport := 1024 + r.Intn(60000)
		fmt.Fprintln(w.ssl, s.aiSSLLine(at, client, sport, site))
		sent := int64(2000 + r.Intn(60000))
		if site.big && r.Intn(25) == 0 {
			sent = int64(2+r.Intn(8)) << 20 // 上传文档
		}
		fmt.Fprintln(w.forti, s.fortiOutBytes(at.Add(time.Duration(5+r.Intn(50))*time.Second), client, site.ip, 443, false, sent))
	}
	if r.Intn(6) == 0 {
		client := fmt.Sprintf("10.0.0.%d", 40+r.Intn(20))
		fmt.Fprintln(w.dns, s.dnsLine(t.Add(time.Duration(r.Intn(60))*time.Second), client, aiCandidates[r.Intn(len(aiCandidates))], "A", "NOERROR"))
	}
}
