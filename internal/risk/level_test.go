package risk

import (
	"testing"

	"netsa/internal/model"
)

// 等级裁决的核心边界：分类底线、成功升级、结果封顶、标签降级。
func TestFinalize(t *testing.T) {
	cases := []struct {
		name string
		hit  model.Hit
		want model.Severity
	}{
		{
			name: "规则把 SQL 注入写成低危：按分类底线抬到高危",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevLow, Result: model.ResultBlocked},
			want: model.SevHigh,
		},
		{
			name: "已拦截的严重级利用：最高只到高危",
			hit:  model.Hit{Category: "已知漏洞利用", Severity: model.SevCritical, Result: model.ResultBlocked},
			want: model.SevHigh,
		},
		{
			name: "请求失败（目标不存在）：不构成严重",
			hit:  model.Hit{Category: "表达式注入", Severity: model.SevCritical, Result: model.ResultFailed},
			want: model.SevHigh,
		},
		{
			name: "后端异常：载荷可能已到达应用，但没有成功证据，封顶高危",
			hit:  model.Hit{Category: "命令/代码执行", Severity: model.SevCritical, Result: model.ResultError},
			want: model.SevHigh,
		},
		{
			name: "未拦截的漏洞利用：维持规则声明的严重",
			hit:  model.Hit{Category: "已知漏洞利用", Severity: model.SevCritical, Result: model.ResultPassed},
			want: model.SevCritical,
		},
		{
			name: "成功利用：规则只写高危也升为严重",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultSuccess},
			want: model.SevCritical,
		},
		{
			name: "盲打类（表达式注入）成功：同样升为严重",
			hit:  model.Hit{Category: "表达式注入", Severity: model.SevHigh, Result: model.ResultSuccess},
			want: model.SevCritical,
		},
		{
			name: "敏感文件可访问：高危但不判定失陷",
			hit:  model.Hit{Category: "敏感文件探测", Severity: model.SevMedium, Result: model.ResultSuccess},
			want: model.SevHigh,
		},
		{
			name: "未知结果（无法判断）：规则声明严重也不成立",
			hit:  model.Hit{Category: "XSS跨站脚本", Severity: model.SevCritical, Result: model.ResultUnknown},
			want: model.SevHigh,
		},
		{
			name: "带外探测：观察本身即证据，不受结果封顶",
			hit:  model.Hit{Category: "带外探测", Severity: model.SevCritical, Result: model.ResultAllowed},
			want: model.SevCritical,
		},
		{
			name: "主机外连恶意地址：即使被防火墙拦截也维持声明等级",
			hit:  model.Hit{Category: "恶意外连", Severity: model.SevHigh, Result: model.ResultBlocked},
			want: model.SevHigh,
		},
		{
			name: "设备报出的恶意软件通信：保留严重",
			hit:  model.Hit{Category: "恶意软件/远控", Severity: model.SevCritical, Result: model.ResultAllowed},
			want: model.SevCritical,
		},
		{
			name: "仅打标签的观察：不超过低危",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultBlocked, TagOnly: true},
			want: model.SevLow,
		},
		{
			name: "未知分类保持声明等级",
			hit:  model.Hit{Category: "自定义规则", Severity: model.SevMedium, Result: model.ResultPassed},
			want: model.SevMedium,
		},
		{
			name: "越界等级：收敛到合法区间而不是让后续数组越界",
			hit:  model.Hit{Category: "自定义规则", Severity: model.Severity(9), Result: model.ResultPassed},
			want: model.SevCritical,
		},
		{
			name: "设备判定严重但已被拦截：按高危处置",
			hit:  model.Hit{Category: "设备威胁告警", Severity: model.SevCritical, Result: model.ResultBlocked},
			want: model.SevHigh,
		},
	}
	for _, c := range cases {
		h := c.hit
		Finalize(&h)
		if h.Severity != c.want {
			t.Errorf("%s: got %s want %s", c.name, h.Severity, c.want)
		}
		// 幂等：重复裁决结果不变（流水线各环节都会调用一次）
		before := h.Severity
		Finalize(&h)
		if h.Severity != before {
			t.Errorf("%s: 非幂等 %s → %s", c.name, before, h.Severity)
		}
	}
}

// 分类底线覆盖所有已知攻击类型，避免新增分类遗漏导致等级为 info。
func TestFloorCoversCategories(t *testing.T) {
	cats := []string{
		"SQL注入", "XSS跨站脚本", "目录穿越/文件包含", "命令/代码执行", "表达式注入", "SSRF", "XXE", "反序列化",
		"WebShell后门", "已知漏洞利用", "敏感文件探测", "管理后台探测", "扫描器", "网络空间测绘", "自动化工具",
		"协议异常", "CC攻击", "目录扫描", "暴力破解", "端口扫描", "主机探测", "洪水攻击", "IoT僵尸网络",
		"高危服务探测", "威胁情报", "IP伪造", "数据爬取/越权遍历", "可疑外连", "带外探测", "挖矿",
		"DNS隧道", "动态域名", "DGA域名", "账号与权限", "主机安全事件", "设备威胁告警", "恶意软件/远控", "恶意外连",
	}
	for _, c := range cats {
		if _, ok := catFloor[c]; !ok {
			t.Errorf("分类 %q 缺少等级底线", c)
		}
	}
	// 关键利用类的最低等级必须是高危以上
	for _, c := range []string{"SQL注入", "命令/代码执行", "反序列化", "WebShell后门", "已知漏洞利用"} {
		if Floor(c) < model.SevHigh {
			t.Errorf("分类 %q 底线过低: %s", c, Floor(c))
		}
	}
	// 侦察类保持低危，避免背景扫描抬高整体风险
	for _, c := range []string{"扫描器", "端口扫描", "高危服务探测"} {
		if Floor(c) > model.SevLow {
			t.Errorf("分类 %q 底线过高: %s", c, Floor(c))
		}
	}
}

func TestAdjustmentsRecorded(t *testing.T) {
	before := map[[2]model.Severity]int64{}
	for _, a := range Adjustments() {
		before[[2]model.Severity{a.From, a.To}] = a.Count
	}
	h := model.Hit{Category: "已知漏洞利用", Severity: model.SevCritical, Result: model.ResultBlocked}
	Finalize(&h)
	var got int64
	for _, a := range Adjustments() {
		if a.From == model.SevCritical && a.To == model.SevHigh {
			got = a.Count
		}
	}
	if got <= before[[2]model.Severity{model.SevCritical, model.SevHigh}] {
		t.Fatalf("等级调整未被计数: %d", got)
	}
}
