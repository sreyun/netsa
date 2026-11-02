package eval

import (
	"strings"
	"testing"

	"netsa/internal/model"
)

// 内置样本是准确性的回归基线：放宽下面的门槛前，先确认是有意的取舍。
func TestBuiltinCorpus(t *testing.T) {
	cases, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(cases)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	rep.Write(&b, true)
	t.Log("\n" + b.String())
	if rep.Benign < 100 || rep.Attacks < 150 {
		t.Fatalf("样本被意外删减: 正常 %d，攻击 %d", rep.Benign, rep.Attacks)
	}
	if rep.Violations != 0 {
		t.Errorf("%d 条样本不符合期望等级", rep.Violations)
	}
	if rep.BenignCritical != 0 {
		t.Errorf("正常样本不应判为严重: %d", rep.BenignCritical)
	}
	if rep.BenignHigh > 1 { // 已知误报：union select 连写在文字里
		t.Errorf("正常样本高危及以上不超过 1 条: %d", rep.BenignHigh)
	}
	if r := rep.Recall(); r < 0.99 {
		t.Errorf("攻击样本检出率 %.3f 低于 0.99", r)
	}
}

func TestParse(t *testing.T) {
	cases, err := Parse(strings.NewReader("# 注释\n\nbenign\tg\tapp\tGET\t200\t10\tnone\t/a\nattack\tg\tspa\tPOST\t404\t0\t>=high\t/b\tcurl/8\n"))
	if err != nil || len(cases) != 2 || cases[0].UA != defaultUA || cases[1].UA != "curl/8" || cases[1].Status != 404 {
		t.Fatalf("解析: %+v %v", cases, err)
	}
	for name, line := range map[string]string{
		"列数不足":  "benign\tg\tapp",
		"标注无效":  "x\tg\tapp\tGET\t200\t10\tnone\t/a",
		"站点无效":  "benign\tg\tx\tGET\t200\t10\tnone\t/a",
		"状态码无效": "benign\tg\tapp\tGET\tx\t10\tnone\t/a",
		"大小无效":  "benign\tg\tapp\tGET\t200\tx\tnone\t/a",
		"期望无效":  "benign\tg\tapp\tGET\t200\t10\tbad\t/a",
	} {
		if _, err := Parse(strings.NewReader(line)); err == nil {
			t.Errorf("%s 应报错", name)
		}
	}
}

func TestExpect(t *testing.T) {
	for _, c := range []struct {
		expect  string
		alerted bool
		sev     model.Severity
		ok      bool
	}{
		{"none", false, 0, true}, {"none", true, model.SevLow, false},
		{"<=low", false, 0, true}, {"<=low", true, model.SevLow, true}, {"<=low", true, model.SevHigh, false},
		{">=high", true, model.SevCritical, true}, {">=high", true, model.SevLow, false}, {">=high", false, 0, false},
		{"=high", true, model.SevHigh, true}, {"=high", true, model.SevCritical, false},
		{"-", true, model.SevCritical, true},
	} {
		r := Result{Case: Case{Expect: c.expect}, Alerted: c.alerted, Severity: c.sev}
		if r.check() != c.ok {
			t.Errorf("%+v", c)
		}
	}
}
