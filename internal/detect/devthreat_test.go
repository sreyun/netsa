package detect

import (
	"testing"

	"netsa/internal/model"
)

// 防火墙攻击防范、入侵防御日志的攻击类型（含深信服的中文名称）归入本系统的攻击分类。
func TestDeviceThreatCategories(t *testing.T) {
	for name, want := range map[string]string{
		"Syn flood attack":           CatFlood,
		"SYN Flood":                  CatFlood,
		"Port scan attack":           CatPortScan,
		"IP sweep":                   CatHostSweep,
		"Land attack":                CatFlood,
		"Smurf attack":               CatFlood,
		"Ping of death":              CatFlood,
		"IP spoofing attack":         CatSpoof,
		"TCP null flag attack":       CatProtocol,
		"Traceroute":                 CatProtocol,
		"SYN洪水攻击":                    CatFlood,
		"端口扫描":                       CatPortScan,
		"IP地址扫描":                     CatHostSweep,
		"SQL注入":                      CatSQLi,
		"跨站脚本攻击":                     CatXSS,
		"命令注入":                       CatCmdExec,
		"僵尸网络通信":                     "恶意软件/远控",
		"WebLogic反序列化漏洞":             CatDeser,
		"Apache Struts2 OGNL 远程代码执行": CatExpr,
	} {
		h := deviceThreatHit(&model.Event{Kind: model.KindFirewall, Format: "atk", Threat: name, DstIP: "10.0.0.10", Action: model.ActionDeny})
		if h.Category != want {
			t.Errorf("%s 应归为 %s，实际 %s", name, want, h.Category)
		}
	}
	// 普通词里含有关键字的字母不算（windows 不是 dos，island 不是 land）
	for _, name := range []string{"Windows SMB Remote Code Execution", "Island Exploit Kit"} {
		if h := deviceThreatHit(&model.Event{Kind: model.KindFirewall, Threat: name}); h.Category == CatFlood {
			t.Errorf("%s 不应归为洪水攻击", name)
		}
	}
}
