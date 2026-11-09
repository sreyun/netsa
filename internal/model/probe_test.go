package model

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 生产环境中出现在“主要目标”里的二进制请求（nginx 记录的请求行解析后）。
func TestProbeLabel(t *testing.T) {
	for raw, want := range map[string]string{
		"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03":                                           "（非 HTTP 请求：TLS 握手）",
		"\x03\x00\x00*%\xe0\x00\x00\x00\x00\x00Cookie: mstshash=nmap":                            "（非 HTTP 请求：RDP）",
		"\x00#9b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03": "（非 HTTP 请求：DNS 查询（TCP））",
		"<policy-file-request/>\x00":                                                             "（非 HTTP 请求：Flash 策略文件请求）",
		"SSH-2.0-Go":                                                                             "（非 HTTP 请求：SSH）",
		"\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00":                                               "（非 HTTP 请求：SMB）",
		"\x00\x00\x00\x1d\xd5\xa1\xc3\xbf\xe0\xd1\xb4\xcf":                                       "（非 HTTP 请求：二进制数据）",
		"\x00\x0e8\x9d\x8b\x00\x9f\xa1 \xc2\x8f\x00\x00\x00\x00\x00":                             "（非 HTTP 请求：二进制数据）",
		"HELP": "（非 HTTP 请求：HELP）",
	} {
		if got := ProbeLabel(raw); got != want {
			t.Errorf("%q: %s，期望 %s", raw, got, want)
		}
	}
}

func TestWebTargetReadable(t *testing.T) {
	ev := &Event{Kind: KindWeb, Host: "mg.hc-yun.com", URI: "\x00\x00\x00\x1d\xd5\xa1\xc3\xbf"}
	if got := ev.Target(); got != "mg.hc-yun.com （非 HTTP 请求：二进制数据）" {
		t.Fatalf("二进制请求: %q", got)
	}
	// 正常请求不变；URI 中的控制字符转义（空字节截断等攻击载荷仍然可见）
	ev = &Event{Kind: KindWeb, Host: "shop.example.com", Method: "GET", URI: "/商品/列表?id=1"}
	if got := ev.Target(); got != "shop.example.com /商品/列表?id=1" {
		t.Fatalf("正常请求不应改变: %q", got)
	}
	ev = &Event{Kind: KindWeb, Host: "shop.example.com", Method: "GET", URI: "/index.php\x00.jpg"}
	if got := ev.Target(); got != `shop.example.com /index.php\x00.jpg` {
		t.Fatalf("控制字符应转义: %q", got)
	}
	ev = &Event{Kind: KindWeb, Method: "GET", URI: "/"}
	if got := ev.Target(); got != "- /" {
		t.Fatalf("没有站点: %q", got)
	}
}

// 旧版本保存的目标：二进制请求按协议说明，控制字符转义；已经整理过的原样返回（幂等）。
func TestCleanTarget(t *testing.T) {
	for in, want := range map[string]string{
		"mg.hc-yun.com \x00#9b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00": "mg.hc-yun.com （非 HTTP 请求：DNS 查询（TCP））",
		"mg.hc-yun.com <policy-file-request/>\x00":                      "mg.hc-yun.com （非 HTTP 请求：Flash 策略文件请求）",
		"mg.hc-yun.com \x03\x00\x00*%\xe0\x00Cookie: mstshash=nmap":     "mg.hc-yun.com （非 HTTP 请求：RDP）",
		"shop.example.com /a\x00b":                                      `shop.example.com /a\x00b`,
		"shop.example.com /正常/路径":                                       "shop.example.com /正常/路径",
		"43.242.97.44:2408/tcp":                                         "43.242.97.44:2408/tcp",
		"SSH 账号 root @10.0.0.5":                                         "SSH 账号 root @10.0.0.5",
	} {
		got := CleanTarget(in)
		if got != want {
			t.Errorf("%q → %q，期望 %q", in, got, want)
		}
		if CleanTarget(got) != got || !utf8.ValidString(got) || strings.ContainsAny(got, "\x00\x01\x7f") {
			t.Errorf("整理结果应可读且幂等: %q", got)
		}
	}
}

// 二进制载荷逐字节转义：随机字节恰好构成的合法 UTF-8（\xd5\xa1 → ա）不再显示成零散的怪字；可读文本照常显示。
func TestPrintableBinary(t *testing.T) {
	if got := PrintableBinary("\x00\x00\x00\x1d\xd5\xa1\xc3\xbf", 0); got != `\x00\x00\x00\x1d\xd5\xa1\xc3\xbf` {
		t.Fatalf("二进制: %s", got)
	}
	if got := PrintableBinary("SSH-2.0-OpenSSH 中文", 0); got != "SSH-2.0-OpenSSH 中文" {
		t.Fatalf("可读文本: %s", got)
	}
	if got := PrintableBinary("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", 12); got != `\x16\x03\x01…` {
		t.Fatalf("截断: %s", got)
	}
}

// 截断不能把多字节字符截成半个（页面上会显示为 �）。
func TestClip(t *testing.T) {
	s := "攻击源abc"
	for n := 0; n <= len(s)+2; n++ {
		got := Clip(s, n)
		if len(got) > n || !utf8.ValidString(got) || !strings.HasPrefix(s, got) {
			t.Fatalf("Clip(%d) = %q", n, got)
		}
	}
	if Clip(s, 4) != "攻" || Clip(s, 9) != "攻击源" || Clip(s, 100) != s {
		t.Fatal("截断位置不对")
	}
}
