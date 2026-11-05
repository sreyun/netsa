package detect

import (
	"os"
	"strings"
	"testing"

	"netsa/internal/model"
)

// 国产 OA 的漏洞接口签名：带载荷的判为已知漏洞利用并注明编号，只访问接口的判为漏洞接口探测（最高中危）。
func TestVulnSignatures(t *testing.T) {
	if VulnSigCount() < 200 {
		t.Fatalf("签名数 %d", VulnSigCount())
	}
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		method, uri, rule, cat string
		sev                    model.Severity
	}{
		// 带穿越载荷：已知漏洞利用，注明 CNVD 编号
		{"GET", "/seeyon/webmail.do?method=doDownloadAtt&filename=index.jsp&filePath=../conf/datasourceCtp.properties", "vp-cnvd-2020-62422", CatCVE, model.SevHigh},
		// 只访问接口（载荷在请求体里）
		{"POST", "/servlet/~ic/bsh.servlet.BshServlet", "vp-cnvd-2021-30167", CatVulnEndpoint, model.SevMedium},
		{"POST", "/seeyon/htmlofficeservlet", "vp-cnvd-2019-19299", CatVulnEndpoint, model.SevMedium},
		// ;参数绕过、重复的 /
		{"POST", "/seeyon//htmlofficeservlet;.js", "vp-cnvd-2019-19299", CatVulnEndpoint, model.SevMedium},
		// 路径前缀是变量（部署目录）
		{"GET", "/jeecg-boot/sys/dict/loadTreeData?pid=0&pidField=1&hasChildField=1&converIsLeafVal=1&tableName=sys_user&text=1&code=1&condition=1", "vp-cve-2023-38992", CatVulnEndpoint, model.SevMedium},
	} {
		var got *model.Hit
		hits := e.Inspect(web(c.method, c.uri, 200, "Mozilla/5.0"))
		for i := range hits {
			if hits[i].RuleID == c.rule {
				got = &hits[i]
			}
		}
		if got == nil {
			t.Errorf("%s %s 应命中 %s：%+v", c.method, c.uri, c.rule, hits)
			continue
		}
		if got.Category != c.cat || got.Severity != c.sev {
			t.Errorf("%s: %s %s，期望 %s %s", c.uri, got.Category, got.Severity, c.cat, c.sev)
		}
		if !strings.Contains(got.Name, "OA") && !strings.Contains(got.Name, "用友") && !strings.Contains(got.Name, "Jeecg") {
			t.Errorf("名称应注明产品: %s", got.Name)
		}
	}
	// 扫描器用 GET 确认 POST 接口是否存在，同样是在探测漏洞接口
	if h := hitIDs(e.Inspect(web("GET", "/seeyon/htmlofficeservlet", 200, "Mozilla/5.0")))["vp-cnvd-2019-19299"]; h.Category != CatVulnEndpoint {
		t.Errorf("GET 探测: %+v", h)
	}
	// 选择功能的参数不同（正常的邮件列表）、相似但不同的路径：不命中
	for _, c := range []struct{ method, uri string }{
		{"GET", "/seeyon/webmail.do?method=list&filename=a&filePath=b"},
		{"POST", "/seeyon/htmlofficeservlet2"},
		{"GET", "/products/webmail.do"},
	} {
		for _, h := range e.Inspect(web(c.method, c.uri, 200, "Mozilla/5.0")) {
			if strings.HasPrefix(h.RuleID, "vp-") {
				t.Errorf("%s %s 不应命中 %s", c.method, c.uri, h.RuleID)
			}
		}
	}
	if VulnVendorOf("vp-cnvd-2019-19299") != "seeyon" || VulnMarker("seeyon") != "seeyon" || VulnMarker("api") != "" {
		t.Error("产品与目录")
	}
	if v, ok := VulnVendorInfo("weaver"); !ok || v.Name != "泛微OA" || v.Lang != "java" {
		t.Errorf("%+v", v)
	}
}

// 生成签名时一并写出的原始模板请求（保留大小写与编码，变量填上随机值），都要能认出对应产品的漏洞接口。
// 改动归一化逻辑（解码、;参数、查询参数拆分）后，这里会先发现漏判。
func TestVulnSamplesRecognized(t *testing.T) {
	data, err := os.ReadFile("testdata/vulnpaths_samples.tsv")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		c := strings.SplitN(line, "\t", 3)
		if len(c) != 3 {
			continue
		}
		n++
		want := VulnVendorOf("vp-" + c[0])
		found := false
		for _, h := range e.Inspect(web(c[1], c[2], 200, "Mozilla/5.0")) {
			found = found || strings.HasPrefix(h.RuleID, "vp-") && VulnVendorOf(h.RuleID) == want
		}
		if !found {
			t.Errorf("%s 未认出：%s %s", c[0], c[1], c[2])
		}
	}
	if n < 200 {
		t.Fatalf("样例 %d 条", n)
	}
}

func BenchmarkMatchVulnMiss(b *testing.B) {
	for i := 0; i < b.N; i++ {
		matchVuln("GET", "/api/v1/orders/1024/items", "/api/v1/orders/1024/items?page=2&size=20")
	}
}
