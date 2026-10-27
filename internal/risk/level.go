// Package risk 集中裁决威胁等级，避免「规则声明 + 各处临时加减」导致同类事件等级不一致。
//
// 一条命中从产生到入库要经过若干环节（特征规则、设备告警、资产漏洞关联、响应复核），
// 每个环节都可能调整等级。如果各环节各自「+1 / -1 / 直接赋值」，就会出现：
//   - 规则写错等级（如把 SQL 注入写成 low）后无人纠正，高危信号被永久漏掉；
//   - 已拦截的漏洞探测与真正利用成功同样标为「严重」，严重级别失去区分度；
//   - 复核为未成功的命中只降一级，仍然停在「严重」。
//
// 因此把最终等级收敛为一处：先抬到分类底线，再按结果升级或封顶，最后做严重级准入。
// 该函数是幂等的：对同一命中重复调用结果不变，便于在流水线各环节（检测后、资产关联后、
// 响应复核后）各自调用一次而无需关心顺序。
package risk

import (
	"sync/atomic"

	"netsa/internal/model"
)

// 攻击分类到最低等级的映射。
//
// 底线的作用是「防漏」：规则作者把高危攻击误写成 low，或自定义规则随手填 info 时，
// 仍能保证该类攻击至少按下列等级处置。设定原则：
//   - 可直接获取数据或执行代码的（注入、反序列化、代码执行、WebShell、已知漏洞、文件读取）→ 高危
//   - 带外证据（OOB）本身就是漏洞已被触发的证明 → 严重
//   - 主机侧失陷迹象（远控外连、挖矿）→ 高危
//   - 侦察类（扫描、探测、目录扫描）→ 低危，避免背景扫描抬高整体风险
var catFloor = map[string]model.Severity{
	"SQL注入":      model.SevHigh,
	"命令/代码执行":    model.SevHigh,
	"表达式注入":      model.SevHigh,
	"反序列化":       model.SevHigh,
	"WebShell后门": model.SevHigh,
	"已知漏洞利用":     model.SevHigh,
	"目录穿越/文件包含":  model.SevHigh,
	"XXE":        model.SevHigh,
	"SSRF":       model.SevHigh,
	"XSS跨站脚本":    model.SevMedium,
	"敏感文件探测":     model.SevMedium,
	"管理后台探测":     model.SevLow, // 后台路径探测是常见背景扫描；是否可访问由暴露面评估单独统计
	"暴力破解":       model.SevMedium,
	"账号与权限":      model.SevMedium,
	"主机安全事件":     model.SevMedium,
	"CC攻击":       model.SevMedium,
	"洪水攻击":       model.SevMedium,
	"设备威胁告警":     model.SevLow, // 设备已给出自身等级，未归类时只做兜底，不抬高
	"威胁情报":       model.SevLow,
	"IP伪造":       model.SevLow,
	"扫描器":        model.SevLow,
	"网络空间测绘":     model.SevLow,
	"目录扫描":       model.SevLow,
	"端口扫描":       model.SevLow,
	"主机探测":       model.SevLow,
	"高危服务探测":     model.SevLow,
	"IoT僵尸网络":    model.SevLow,
	"自动化工具":      model.SevLow,
	"协议异常":       model.SevLow,
	"数据爬取/越权遍历":  model.SevLow,
	"可疑外连":       model.SevMedium,
	"恶意外连":       model.SevMedium, // 主动连接情报标记的地址；等级由情报类型决定（C2 严重、Tor 中危）
	"恶意软件/远控":    model.SevHigh,   // 设备已明确判定为木马 / 远控通信
	"挖矿":         model.SevHigh,
	"DNS隧道":      model.SevMedium,
	"动态域名":       model.SevLow,
	"DGA域名":      model.SevLow,
	"带外探测":       model.SevCritical,
}

// responseProvable 是「响应码 / 响应大小可以判定攻击是否成功」的分类。
//
// 只有这些分类才会把 2xx 当作成功证据；其余分类（Log4j / OGNL / SSTI、SSRF、XXE、
// 反序列化）多为盲打或带外利用，页面正常返回 200 是常态，一律标注为「未拦截」，
// 避免把正常响应误判为失陷。
var responseProvable = map[string]bool{
	"SQL注入":      true,
	"目录穿越/文件包含":  true,
	"命令/代码执行":    true,
	"WebShell后门": true,
	"已知漏洞利用":     true,
	"敏感文件探测":     true,
}

// successEscalates 是「确认利用成功后直接升为严重」的分类。
//
// 这些分类一旦确认成功，意味着目标已被读取数据或执行代码，按严重处置。
// 敏感文件探测虽然能从 200 证明资源可访问，但不足以判定失陷，故不在其中（按高危处理）。
var successEscalates = map[string]bool{
	"SQL注入":      true,
	"命令/代码执行":    true,
	"表达式注入":      true,
	"反序列化":       true,
	"WebShell后门": true,
	"已知漏洞利用":     true,
	"目录穿越/文件包含":  true,
	"XXE":        true,
	"SSRF":       true,
}

// compromiseEvidence 是「观察本身即为失陷证据」的分类：不受响应结果的封顶约束。
//
// 例如内网主机解析 DNSLog 域名，日志里不存在「是否被拦截」的概念，这条记录本身就是
// 漏洞被触发的证据；主机日志被清除、安装计划任务同理。
var compromiseEvidence = map[string]bool{
	"带外探测":    true,
	"恶意外连":    true, // 内网主机主动连接受情报标记的 C2 / 矿池地址
	"可疑外连":    true, // 周期性外连（C2 心跳特征）
	"恶意软件/远控": true, // 设备报出的木马 / 远控通信
	"挖矿":      true,
	"主机安全事件":  true,
	"账号与权限":   true,
}

// Floor 返回分类的最低等级；未知分类返回 info。
func Floor(category string) model.Severity {
	return catFloor[category]
}

// ResponseProvable 判断该分类能否用响应判定攻击是否成功。
// 检测引擎用它决定 2xx 响应是否可作为成功证据（不能作为证据的分类一律标注为「未拦截」）。
func ResponseProvable(category string) bool { return responseProvable[category] }

// SuccessEscalates 判断该分类确认成功后是否直接升为严重。
func SuccessEscalates(category string) bool { return successEscalates[category] }

// CompromiseEvidence 判断分类是否属于「观察即证据」。
func CompromiseEvidence(category string) bool { return compromiseEvidence[category] }

// Finalize 按固定优先级收敛命中的最终等级：
//
//  1. 分类底线：低于底线的抬到下限（防漏配）；
//  2. 严重级准入：
//     - 成功利用（Result=success）且分类可升级 → 严重；
//     - 失陷迹象类（带外、远控、挖矿、主机事件）按规则声明，最高可到严重；
//  3. 结果封顶：已拦截 / 请求失败 / 后端异常 → 不超过高危（未成功就不构成「严重」）；
//     未拦截（passed）保留规则声明，但只有可升级分类才允许停在严重；
//  4. 标签命中：仅打标签的观察不超过低危。
//
// 判定顺序即优先级：结果封顶在成功升级之后，保证「已拦截」永远不会因规则声明为
// critical 而继续标为严重；标签降级最后执行，保证 tag_only 规则不会因分类底线反弹。
func Finalize(h *model.Hit) {
	if h == nil {
		return
	}
	before := h.Severity
	sev := h.Severity
	// 防御性收敛到合法区间：等级来自规则 / 设备 / 代码，任何越界值都不应影响后续
	// levelFloor 的数组下标或排序比较（越界会直接 panic，属于稳定性问题）。
	if sev < model.SevInfo {
		sev = model.SevInfo
	}
	if sev > model.SevCritical {
		sev = model.SevCritical
	}
	if f := catFloor[h.Category]; sev < f {
		sev = f
	}

	// 2. 严重级准入
	switch {
	case h.Result == model.ResultSuccess && successEscalates[h.Category]:
		sev = model.SevCritical
	case h.Result == model.ResultSuccess && h.Category == "敏感文件探测" && sev < model.SevHigh:
		// 敏感文件能取到 200：资源确实可访问，属于「已验证的暴露面」，按高危处置但不判定失陷
		sev = model.SevHigh
	case sev >= model.SevCritical && !compromiseEvidence[h.Category] &&
		h.Result != model.ResultSuccess && h.Result != model.ResultPassed:
		// 既没有成功证据，也不是「未拦截」：不构成严重
		sev = model.SevHigh
	}

	// 3. 结果封顶
	switch h.Result {
	case model.ResultBlocked, model.ResultFailed, model.ResultError:
		if !compromiseEvidence[h.Category] && sev > model.SevHigh {
			sev = model.SevHigh
		}
	}

	// 4. 仅打标签的观察不参与告警分级
	if h.TagOnly && sev > model.SevLow {
		sev = model.SevLow
	}
	h.Severity = sev
	if sev != before && validSev(before) && validSev(sev) {
		adjust[before][sev].Add(1)
	}
}

func validSev(s model.Severity) bool { return s >= model.SevInfo && s <= model.SevCritical }

// Adjust 是一次等级调整的累计次数。
type Adjust struct {
	From  model.Severity
	To    model.Severity
	Count int64
}

// adjust 记录等级被策略调整的次数（from → to），用于监控「规则声明与实际判定」的偏差。
var adjust [5][5]atomic.Int64

// Adjustments 返回非零的等级调整计数。
func Adjustments() []Adjust {
	var out []Adjust
	for from := range adjust {
		for to := range adjust[from] {
			if n := adjust[from][to].Load(); n > 0 {
				out = append(out, Adjust{From: model.Severity(from), To: model.Severity(to), Count: n})
			}
		}
	}
	return out
}

// Describe 返回等级裁决依据，用于告警证据与排障（例如「已拦截，最高按高危处置」）。
// 返回空字符串表示未发生调整。
func Describe(h *model.Hit, before model.Severity) string {
	if h == nil || h.Severity == before {
		return ""
	}
	switch {
	case h.Severity > before:
		if h.Severity == model.SevCritical && h.Result == model.ResultSuccess {
			return "响应表明利用成功，升为严重"
		}
		return "按攻击分类底线抬升"
	case h.TagOnly:
		return "仅打标签，不计入告警分级"
	case h.Result == model.ResultBlocked:
		return "已被拦截，最高按高危处置"
	case h.Result == model.ResultFailed || h.Result == model.ResultError:
		return "请求未成功，最高按高危处置"
	default:
		return "缺少成功证据，最高按高危处置"
	}
}
