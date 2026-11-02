package risk

import (
	"strings"
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
			name: "未拦截的漏洞利用：没有第二份证据只到高危",
			hit:  model.Hit{Category: "已知漏洞利用", Severity: model.SevCritical, Result: model.ResultPassed},
			want: model.SevHigh,
		},
		{
			name: "未拦截的漏洞利用：有第二份证据维持严重",
			hit:  model.Hit{Category: "已知漏洞利用", Severity: model.SevCritical, Result: model.ResultPassed, Proven: true},
			want: model.SevCritical,
		},
		{
			name: "只有响应码的疑似成功：规则写严重也只到高危",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevCritical, Result: model.ResultSuccess},
			want: model.SevHigh,
		},
		{
			name: "有第二份证据的成功利用：规则只写高危也升为严重",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultSuccess, Proven: true},
			want: model.SevCritical,
		},
		{
			name: "日志直接证明的成功（暴力破解后登录）：不需要第二份证据",
			hit:  model.Hit{Category: "暴力破解", Severity: model.SevCritical, Result: model.ResultSuccess},
			want: model.SevCritical,
		},
		{
			name: "自由文本中的弱特征：不按底线抬升，最高低危",
			hit:  model.Hit{Category: "XSS跨站脚本", Severity: model.SevHigh, Result: model.ResultPassed, Weak: true},
			want: model.SevLow,
		},
		{
			name: "兜底页面返回的 200：底线放宽一级",
			hit:  model.Hit{Category: "WebShell后门", Severity: model.SevMedium, Result: model.ResultPassed, Disproven: true},
			want: model.SevMedium,
		},
		{
			name: "盲打类（表达式注入）成功：有证据同样升为严重",
			hit:  model.Hit{Category: "表达式注入", Severity: model.SevHigh, Result: model.ResultSuccess, Proven: true},
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
			name: "仅打标签的弱特征（空 UA）：不按分类底线抬升，保持信息级",
			hit:  model.Hit{Category: "自动化工具", Severity: model.SevInfo, TagOnly: true},
			want: model.SevInfo,
		},
		{
			name: "未到达服务的端口探测降为标签：保持信息级",
			hit:  model.Hit{Category: "高危服务探测", Severity: model.SevInfo, Result: model.ResultAllowed, TagOnly: true},
			want: model.SevInfo,
		},
		{
			name: "自学习下调的注入命中：最多低于底线一级（高危底线 → 中危）",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevMedium, Result: model.ResultBlocked, Learned: -1},
			want: model.SevMedium,
		},
		{
			name: "自学习下调也不能越过底线两级",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevLow, Result: model.ResultBlocked, Learned: -1},
			want: model.SevMedium,
		},
		{
			name: "自学习下调但有证据证明利用成功：仍升为严重",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevMedium, Result: model.ResultSuccess, Learned: -1, Proven: true},
			want: model.SevCritical,
		},
		{
			name: "自学习下调且只有响应码：校准生效",
			hit:  model.Hit{Category: "SQL注入", Severity: model.SevMedium, Result: model.ResultSuccess, Learned: -1},
			want: model.SevMedium,
		},
		{
			name: "自学习下调的低危底线分类：不低于低危",
			hit:  model.Hit{Category: "扫描器", Severity: model.SevInfo, Learned: -1},
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
			want: model.SevHigh,
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

// 等级调整的说明写在告警证据里，分析员据此判断为什么是这个等级。
func TestDescribe(t *testing.T) {
	cases := []struct {
		name   string
		hit    model.Hit
		before model.Severity
		want   string
	}{
		{"没有调整", model.Hit{Severity: model.SevHigh}, model.SevHigh, ""},
		{"有证据升为严重", model.Hit{Severity: model.SevCritical, Result: model.ResultSuccess}, model.SevHigh, "有证据"},
		{"底线抬升", model.Hit{Severity: model.SevHigh}, model.SevLow, "底线"},
		{"标签", model.Hit{Severity: model.SevLow, TagOnly: true}, model.SevHigh, "标签"},
		{"普通文字", model.Hit{Severity: model.SevLow, Weak: true}, model.SevHigh, "普通文字"},
		{"只有响应码", model.Hit{Severity: model.SevHigh, Result: model.ResultSuccess}, model.SevCritical, "只有响应码"},
		{"已拦截", model.Hit{Severity: model.SevHigh, Result: model.ResultBlocked}, model.SevCritical, "拦截"},
		{"失败", model.Hit{Severity: model.SevHigh, Result: model.ResultFailed}, model.SevCritical, "未成功"},
		{"后端异常", model.Hit{Severity: model.SevHigh, Result: model.ResultError}, model.SevCritical, "未成功"},
		{"缺少证据", model.Hit{Severity: model.SevHigh, Result: model.ResultPassed}, model.SevCritical, "缺少成功证据"},
	}
	for _, c := range cases {
		got := Describe(&c.hit, c.before)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q，期望包含 %q", c.name, got, c.want)
		}
	}
	if Describe(nil, model.SevHigh) != "" {
		t.Error("nil 命中应返回空")
	}
	Finalize(nil) // 不应崩溃
}

func TestCategoryPredicates(t *testing.T) {
	if Floor("SQL注入") != model.SevHigh || Floor("不存在的分类") != model.SevInfo {
		t.Error("分类底线")
	}
	if !ResponseProvable("SQL注入") || ResponseProvable("SSRF") {
		t.Error("响应可判定的分类")
	}
	if !SuccessEscalates("SSRF") || SuccessEscalates("敏感文件探测") {
		t.Error("可升级的分类")
	}
	if !CompromiseEvidence("带外探测") || CompromiseEvidence("SQL注入") {
		t.Error("失陷迹象分类")
	}
}

// 证据改变不了已拦截的结果：严重级准入和结果封顶的顺序不能颠倒。
func TestProvenCannotOverrideBlocked(t *testing.T) {
	for _, r := range []string{model.ResultBlocked, model.ResultFailed, model.ResultError} {
		h := model.Hit{Category: "SQL注入", Severity: model.SevCritical, Result: r, Proven: true}
		Finalize(&h)
		if h.Severity != model.SevHigh {
			t.Errorf("%s 不应达到严重: %s", r, h.Severity)
		}
	}
	// 幂等：多次裁决结果不变
	h := model.Hit{Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultSuccess, Proven: true}
	Finalize(&h)
	Finalize(&h)
	if h.Severity != model.SevCritical {
		t.Errorf("应保持严重: %s", h.Severity)
	}
	w := model.Hit{Category: "XSS跨站脚本", Severity: model.SevCritical, Result: model.ResultPassed, Weak: true}
	Finalize(&w)
	Finalize(&w)
	if w.Severity != model.SevLow {
		t.Errorf("弱特征应保持低危: %s", w.Severity)
	}
}
