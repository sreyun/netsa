package api

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"netsa/internal/assets"
	"netsa/internal/model"
	"netsa/internal/store"
)

// reportCSS 是报告页的样式：A4 打印友好，邮件客户端中也能正常显示（只使用内联样式表，不依赖脚本）。
const reportCSS = `
body{font-family:"PingFang SC","Microsoft YaHei","Noto Sans CJK SC",Arial,sans-serif;color:#1f2937;background:#f3f4f6;margin:0;padding:24px;font-size:13px;line-height:1.6}
.page{max-width:960px;margin:0 auto;background:#fff;padding:32px 40px;border-radius:8px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px;padding-left:8px;border-left:4px solid #2563eb}
.meta{color:#6b7280;font-size:12px}.toolbar{margin:12px 0 0}.toolbar button{padding:6px 14px;border:1px solid #2563eb;background:#2563eb;color:#fff;border-radius:4px;cursor:pointer}
.kpis{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0}.kpi{flex:1 1 140px;border:1px solid #e5e7eb;border-radius:6px;padding:10px 12px}
.kpi b{display:block;font-size:20px;color:#111827}.kpi span{color:#6b7280;font-size:12px}
.summary li{margin:4px 0}table{width:100%;border-collapse:collapse;margin:6px 0}th,td{border-bottom:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f9fafb;color:#374151;font-weight:600}td.n{text-align:right;white-space:nowrap}.bar{background:#dbeafe;height:10px;border-radius:2px}
.bar i{display:block;height:10px;background:#2563eb;border-radius:2px}.tag{display:inline-block;padding:0 6px;border-radius:3px;font-size:12px;color:#fff}
.s4{background:#b91c1c}.s3{background:#ea580c}.s2{background:#ca8a04}.s1{background:#2563eb}.s0{background:#6b7280}
.ok{color:#15803d}.warn{color:#b45309}.bad{color:#b91c1c}.na{color:#6b7280}.note{color:#6b7280;font-size:12px}.foot{margin-top:28px;color:#9ca3af;font-size:12px;border-top:1px solid #e5e7eb;padding-top:10px}
@media print{body{background:#fff;padding:0}.page{padding:0;max-width:none}.toolbar{display:none}h2{break-after:avoid}tr{break-inside:avoid}@page{size:A4;margin:14mm}}
`

var reportFuncs = template.FuncMap{
	"sev":     func(s model.Severity) string { return s.Label() },
	"sevi":    func(s model.Severity) int { return int(s) },
	"human":   human,
	"pct":     func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"dt":      func(t time.Time) string { return t.Format("2006-01-02 15:04") },
	"status":  func(s string) string { return store.IncidentStatusLabel[s] },
	"imp":     func(s string) string { return assets.LevelLabel[s] },
	"sevname": func(s string) string { return model.ParseSeverity(s).Label() },
	"high":    sevTotal,
	"css":     func() template.CSS { return template.CSS(reportCSS) },
	"add":     func(a, b int) int { return a + b },
	"dur":     cnDuration,
}

var periodTpl = template.Must(template.New("period").Funcs(reportFuncs).Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.R.Title}}</title>
<style>{{css}}</style></head><body><div class="page">
<h1>{{if .R.Org}}{{.R.Org}} · {{end}}{{.R.Title}}</h1>
<div class="meta">统计范围 {{.R.From}} ~ {{.R.To}}（对比 {{.R.PrevFrom}} ~ {{.R.PrevTo}}）· 生成时间 {{dt .R.Generated}} · netsa 网络安全态势感知平台</div>
{{if .Print}}<div class="toolbar"><button id="print">打印 / 导出 PDF</button></div><script src="/print.js"></script>{{end}}
<div class="kpis">
<div class="kpi"><b>{{.R.Score}}</b><span>安全评分（{{.R.GradeLabel}}）</span></div>
<div class="kpi"><b>{{human .R.Totals.Attacks}}</b><span>攻击次数（上期 {{human .R.Prev.Attacks}}）</span></div>
<div class="kpi"><b>{{.R.Totals.Attackers}}</b><span>攻击源（新增 {{.R.Totals.NewAttackers}}）</span></div>
<div class="kpi"><b class="{{if .R.Totals.Success}}bad{{else}}ok{{end}}">{{.R.Totals.Success}}</b><span>疑似攻击成功</span></div>
<div class="kpi"><b>{{.R.Incidents.Created}} / {{.R.Incidents.Closed}}</b><span>新建 / 关闭事件</span></div>
<div class="kpi"><b>{{if ge .R.Incidents.SLARate 0.0}}{{pct .R.Incidents.SLARate}}{{else}}-{{end}}</b><span>按时处置率</span></div>
</div>
<h2>一、总体结论</h2><ul class="summary">{{range .R.Summary}}<li>{{.}}</li>{{end}}</ul>
{{range .R.Notes}}<p class="note">注：{{.}}</p>{{end}}
<h2>二、攻击趋势</h2><table><tr><th style="width:70px">日期</th><th>攻击次数</th><th class="n" style="width:80px">攻击</th><th class="n" style="width:70px">告警</th><th class="n" style="width:80px">疑似成功</th></tr>
{{range .R.Daily}}<tr><td>{{.Date}}</td><td><div class="bar"><i style="width:{{.Pct}}%"></i></div></td><td class="n">{{human .Attacks}}</td><td class="n">{{.Alerts}}</td><td class="n">{{.Success}}</td></tr>{{end}}</table>
<p class="note">中危及以上攻击 {{human (high .R.Totals)}} 次；严重 {{index .R.Totals.Sev 4}}、高危 {{index .R.Totals.Sev 3}}、中危 {{index .R.Totals.Sev 2}}、低危 {{index .R.Totals.Sev 1}}。已拦截 {{human .R.Totals.Blocked}} 次。</p>
<h2>三、攻击类型与来源</h2>
<table><tr><th>攻击类型 TOP 10</th><th class="n">次数</th></tr>{{range .R.Categories}}<tr><td>{{.Name}}</td><td class="n">{{human .Value}}</td></tr>{{else}}<tr><td colspan="2" class="na">无</td></tr>{{end}}</table>
<table><tr><th>攻击源 TOP 10</th><th>归属 / 威胁等级 / 攻击类型</th><th class="n">攻击次数</th></tr>{{range .R.Attackers}}<tr><td>{{.Name}}</td><td>{{.Detail}}</td><td class="n">{{human .Value}}</td></tr>{{else}}<tr><td colspan="3" class="na">无</td></tr>{{end}}</table>
<table><tr><th>来源国家 / 地区 TOP 10</th><th class="n">攻击次数</th></tr>{{range .R.Countries}}<tr><td>{{.Name}}</td><td class="n">{{human .Value}}</td></tr>{{else}}<tr><td colspan="2" class="na">无</td></tr>{{end}}</table>
<h2>四、安全事件处置</h2>
<p>期间新建事件 {{.R.Incidents.Created}} 个、关闭 {{.R.Incidents.Closed}} 个（其中误报 {{.R.Incidents.FalsePositive}} 个），{{if .R.Incidents.MTTR}}平均处置时长 {{dur .R.Incidents.MTTR}}，{{end}}当前未关闭 {{.R.Incidents.OpenNow}} 个，超时 <b class="{{if .R.Incidents.OverdueNow}}bad{{else}}ok{{end}}">{{.R.Incidents.OverdueNow}}</b> 个。</p>
<table><tr><th>事件</th><th>等级</th><th>状态</th><th>负责人</th><th class="n">告警</th><th>首次发现</th></tr>
{{range .R.Incidents.Top}}<tr><td>#{{.ID}} {{.Title}}</td><td><span class="tag s{{sevi .Severity}}">{{sev .Severity}}</span></td><td>{{status .Status}}{{if .Overdue}} <b class="bad">超时</b>{{end}}</td><td>{{.Assignee}}</td><td class="n">{{.Alerts}}</td><td>{{dt .FirstSeen}}</td></tr>{{else}}<tr><td colspan="6" class="na">期间没有新建事件</td></tr>{{end}}</table>
<h2>五、疑似失陷资产</h2>
<table><tr><th>资产</th><th>置信度</th><th>迹象</th><th>处置建议</th></tr>
{{range .R.Compromised}}<tr><td>{{.Asset}}</td><td>{{if eq .Confidence "high"}}<b class="bad">高</b>{{else}}<span class="warn">中</span>{{end}}</td><td>{{range $i, $x := .Indicators}}{{if $i}}；{{end}}{{$x}}{{end}}</td><td>{{.Advice}}</td></tr>{{else}}<tr><td colspan="4" class="ok">未发现疑似失陷资产</td></tr>{{end}}</table>
{{if .R.Vulns}}<h2>六、资产与漏洞</h2>
<p>登记资产 {{.R.Vulns.Assets}} 个（核心 {{index .R.Vulns.ByImportance "core"}}、重要 {{index .R.Vulns.ByImportance "important"}}），未填写负责人 {{.R.Vulns.NoOwner}} 个；漏洞共 {{.R.Vulns.Vulns}} 个，未修复 <b class="{{if .R.Vulns.OpenVulns}}warn{{else}}ok{{end}}">{{.R.Vulns.OpenVulns}}</b> 个（严重 {{index .R.Vulns.OpenBySev "critical"}}、高危 {{index .R.Vulns.OpenBySev "high"}}），已修复 {{.R.Vulns.Fixed}} 个，其中核心资产高危及以上未修复 <b class="{{if .R.Vulns.CoreOpenHigh}}bad{{else}}ok{{end}}">{{.R.Vulns.CoreOpenHigh}}</b> 个。</p>{{end}}
<h2>{{if .R.Vulns}}七{{else}}六{{end}}、优先处置建议</h2>
<table><tr><th style="width:44px">优先级</th><th>事项</th><th>原因</th></tr>{{range .R.Actions}}<tr><td><b>{{.Priority}}</b></td><td>{{.Title}}</td><td>{{.Reason}}</td></tr>{{else}}<tr><td colspan="3" class="ok">暂无</td></tr>{{end}}</table>
<h2>{{if .R.Vulns}}八{{else}}七{{end}}、防护能力评估</h2>
<table><tr><th>维度</th><th class="n">得分</th><th>结论</th></tr>{{range .R.Dimensions}}<tr><td>{{.Name}}</td><td class="n">{{.Score}}</td><td>{{.Summary}}</td></tr>{{end}}</table>
<h2>{{if .R.Vulns}}九{{else}}八{{end}}、数据源运行情况</h2>
<table><tr><th>数据源</th><th>格式</th><th>状态</th><th class="n">日志行数</th><th class="n">解析失败</th></tr>
{{range .R.Sources}}<tr><td>{{.Name}}</td><td>{{.Detected}}</td><td>{{if .Silent}}<b class="bad">断流</b>{{else}}{{.Status}}{{end}}</td><td class="n">{{human .Lines}}</td><td class="n">{{.Failed}}</td></tr>{{else}}<tr><td colspan="5" class="na">无</td></tr>{{end}}</table>
{{if .R.SenderTotal}}<p class="note">syslog 发送端 {{index .R.SenderTotal "senders"}} 个，在线 {{index .R.SenderTotal "online"}}、断流 {{index .R.SenderTotal "silent"}}、被拒绝 {{index .R.SenderTotal "rejected"}}；误报抑制累计过滤 {{.R.Suppressed}} 次命中。</p>{{end}}
<div class="foot">本报告由 netsa 根据接入的日志自动生成，统计口径以日志时间为准。报告中的 IP、资产等信息属于内部敏感信息，请勿外传。</div>
</div></body></html>`))

func renderPeriodHTML(w io.Writer, r *PeriodReport, print bool) error {
	return periodTpl.Execute(w, map[string]any{"R": r, "Print": print})
}
