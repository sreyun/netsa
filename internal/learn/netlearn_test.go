package learn

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// 防火墙自身的 local 域不作为内网依据；一两个地址也不足以认定整个 /24。
func TestObserveInternalZoneNeedsEvidence(t *testing.T) {
	l := newLearner(t, filepath.Join(t.TempDir(), "learn.json"))
	now := time.Now()
	for i := 0; i < 3*netLearnEvents; i++ {
		// 防火墙的外网接口地址出现在 local 域：再多也不能把机房公网段学成内网
		if pfx := l.ObserveInternalZone("43.242.97."+strconv.Itoa(30+i%5), "Local", now); pfx != "" {
			t.Fatalf("local 域不能作为依据: %s", pfx)
		}
	}
	for i := 0; i < 3*netLearnEvents; i++ {
		if pfx := l.ObserveInternalZone("172.168.50."+strconv.Itoa(1+i%2), "trust", now); pfx != "" {
			t.Fatalf("只有两个地址不能认定整个网段: %s", pfx)
		}
	}
	if pfx := l.ObserveInternalZone("172.168.50.3", "trust", now); pfx != "172.168.50.0/24" {
		t.Fatalf("第三个地址出现后应认定，实际 %q", pfx)
	}
	if nets := l.LearnedNets(); len(nets) != 1 || nets[0] != "172.168.50.0/24" {
		t.Fatalf("学到的网段: %v", nets)
	}
	c := l.Report().Changes[0]
	if c.Kind != "intranet" || !strings.Contains(c.Detail, "3 个地址") {
		t.Fatalf("进化日志应写明地址数: %+v", c)
	}
}

// 旧版本依据 local 域学到的内网网段：启动时撤销，记入进化日志并计入自我纠错，只执行一次；其他安全域学到的保留。
func TestDropDeviceZoneNets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learn.json")
	old := `{"intranet":[
		{"prefix":"43.242.97.0/24","zone":"local","events":20,"hosts":["43.242.97.48","43.242.97.32"]},
		{"prefix":"172.168.100.0/24","zone":"trust","events":20,"hosts":["172.168.100.23"]}]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newLearner(t, path)
	if nets := l.LearnedNets(); len(nets) != 1 || nets[0] != "172.168.100.0/24" {
		t.Fatalf("local 域学到的网段应撤销、trust 的保留: %v", nets)
	}
	r := l.Report()
	if r.Loop.NetsOff != 1 {
		t.Fatalf("自我纠错计数: %+v", r.Loop)
	}
	offs := 0
	for _, c := range r.Changes {
		if c.Kind == "intranet_off" {
			offs++
			if !strings.Contains(c.Detail, "43.242.97.0/24") || !strings.Contains(c.Detail, "43.242.97.48") {
				t.Fatalf("撤销说明应写明网段与依据: %s", c.Detail)
			}
		}
	}
	if offs != 1 {
		t.Fatalf("应记录 1 条撤销，实际 %d", offs)
	}
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	// 再次启动：已撤销，不重复记录
	r2 := newLearner(t, path).Report()
	if r2.Loop.NetsOff != 1 || len(r2.Intranet) != 1 {
		t.Fatalf("撤销应只执行一次: loop=%+v nets=%+v", r2.Loop, r2.Intranet)
	}
}

// 回溯与恢复按发生顺序执行：停用后随即重新启用，状态库必须先回溯再恢复。
func TestRetractRestoreOrdered(t *testing.T) {
	l := newLearner(t, filepath.Join(t.TempDir(), "learn.json"))
	var mu sync.Mutex
	var got []string
	done := make(chan struct{})
	const rounds = 200
	l.OnRetract = func(rule, _, _ string) {
		mu.Lock()
		got = append(got, "retract "+rule)
		mu.Unlock()
		time.Sleep(time.Microsecond) // 模拟状态库的写锁等待
	}
	l.OnRestore = func(rule, _, _ string) {
		mu.Lock()
		got = append(got, "restore "+rule)
		if len(got) == 2*rounds {
			close(done)
		}
		mu.Unlock()
	}
	for i := 0; i < rounds; i++ {
		r := "learn-" + strconv.Itoa(i)
		l.retract(r, "", "停用")
		l.restore(r, "", "启用")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("回调没有全部执行")
	}
	for i := 0; i < rounds; i++ {
		r := "learn-" + strconv.Itoa(i)
		if got[2*i] != "retract "+r || got[2*i+1] != "restore "+r {
			t.Fatalf("第 %d 组顺序错误: %v", i, got[2*i:2*i+2])
		}
	}
}
