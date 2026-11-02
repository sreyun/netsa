package block

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/config"
)

func newManager(t *testing.T, cfg config.BlockConfig) *Manager {
	t.Helper()
	cfg.Enabled = true
	m, err := New(Options{Cfg: cfg, Path: filepath.Join(t.TempDir(), "block.json"), Whitelist: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDisabled(t *testing.T) {
	m, err := New(Options{})
	if m != nil || err != nil {
		t.Fatal("未启用应返回 nil")
	}
	if _, err := m.Request("203.0.113.1", "x", 0, 0, "a"); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if m.Active() != nil || m.List(1) != nil || m.Tick() != 0 {
		t.Fatal("nil 方法应安全")
	}
}

// 内网、保留、保护名单、白名单和网段都不能封禁。
func TestProtectedAddresses(t *testing.T) {
	m := newManager(t, config.BlockConfig{Protect: []string{"203.0.113.0/28", "192.0.2.77"}})
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "::1", "fe80::1", "fc00::1", "169.254.169.254", "224.0.0.1", "0.0.0.0",
		"203.0.113.5", "192.0.2.77", "198.51.100.9", "::ffff:10.0.0.1", "203.0.113.0/24", "0.0.0.0/0", "bad", ""} {
		var pe *ProtectedError
		if _, err := m.Request(ip, "x", 0, 0, "ana"); !errors.As(err, &pe) {
			t.Errorf("%q 不应允许封禁: %v", ip, err)
		}
	}
	m2, _ := New(Options{Cfg: config.BlockConfig{Enabled: true}, IsPrivate: func(ip string) bool { return ip == "172.168.100.1" }})
	if _, err := m2.Request("172.168.100.1", "x", 0, 0, "ana"); err == nil {
		t.Error("配置的内网网段不应允许封禁")
	}
	if _, err := New(Options{Cfg: config.BlockConfig{Enabled: true, Protect: []string{"nope"}}}); err == nil {
		t.Error("保护名单格式错误应报错")
	}
}

func TestLifecycle(t *testing.T) {
	m := newManager(t, config.BlockConfig{DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.nowFunc = func() time.Time { return now }
	if _, err := m.Request("203.0.113.100", " ", 0, 0, "ana"); err == nil {
		t.Fatal("必须填写原因")
	}
	it, err := m.Request("203.0.113.100", "暴力破解", 0, 5, "ana")
	if err != nil || it.Status != StatusPending || it.TTL != time.Hour || it.IncidentID != 5 {
		t.Fatalf("申请: %+v %v", it, err)
	}
	if len(m.Active()) != 0 {
		t.Fatal("审批前不能生效")
	}
	// 重复申请返回已有记录
	if dup, _ := m.Request("203.0.113.100", "x", 0, 0, "bob"); dup.ID != it.ID {
		t.Fatalf("重复申请: %+v", dup)
	}
	// 时长不超过上限
	long, _ := m.Request("203.0.113.101", "x", 100*time.Hour, 0, "ana")
	if long.TTL != 2*time.Hour {
		t.Fatalf("时长上限: %v", long.TTL)
	}
	// 不能批准自己的申请
	if _, err := m.Approve(it.ID, "ana"); !errors.Is(err, ErrSelf) {
		t.Fatalf("自己批准: %v", err)
	}
	if _, err := m.Approve(999, "root"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	got, err := m.Approve(it.ID, "root")
	if err != nil || got.Status != StatusActive || !got.Expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("批准: %+v %v", got, err)
	}
	if a := m.Active(); len(a) != 1 || a[0] != "203.0.113.100" {
		t.Fatalf("生效名单: %v", a)
	}
	if _, err := m.Approve(it.ID, "root"); !errors.Is(err, ErrState) {
		t.Fatal("不能重复批准")
	}
	// 重启后保持
	m2, err := New(Options{Cfg: m.opt.Cfg, Path: m.opt.Path})
	if err != nil {
		t.Fatal(err)
	}
	m2.nowFunc = m.nowFunc
	if a := m2.Active(); len(a) != 1 {
		t.Fatalf("重启后: %v", a)
	}
	if n, _ := m2.Request("203.0.113.102", "x", 0, 0, "ana"); n.ID <= long.ID {
		t.Fatalf("编号不能复用: %d", n.ID)
	}
	// 到期自动解除：名单立刻不再包含，后台任务再更新状态
	now = now.Add(time.Hour + time.Second)
	if len(m.Active()) != 0 {
		t.Fatal("到期后不应再下发")
	}
	if m.Tick() != 1 {
		t.Fatal("应解除 1 条")
	}
	if got := m.List(0); got[len(got)-1].Status != StatusExpired {
		t.Fatalf("状态: %+v", got)
	}
	// 到期后可以重新申请
	if again, _ := m.Request("203.0.113.100", "再次出现", 0, 0, "ana"); again.ID == it.ID || again.Status != StatusPending {
		t.Fatalf("重新申请: %+v", again)
	}
}

func TestRejectAndRelease(t *testing.T) {
	m := newManager(t, config.BlockConfig{})
	a, _ := m.Request("203.0.113.1", "x", 0, 0, "ana")
	if r, err := m.Reject(a.ID, "root", "业务 IP"); err != nil || r.Status != StatusRejected || r.Note != "业务 IP" {
		t.Fatalf("驳回: %+v %v", r, err)
	}
	if _, err := m.Approve(a.ID, "root"); !errors.Is(err, ErrState) {
		t.Fatal("已驳回不能批准")
	}
	b, _ := m.Request("203.0.113.2", "x", 0, 0, "ana")
	if _, err := m.Release(b.ID, "root", ""); !errors.Is(err, ErrState) {
		t.Fatal("未生效不能解除")
	}
	m.Approve(b.ID, "root")
	if r, err := m.Release(b.ID, "root", "误封"); err != nil || r.Status != StatusReleased {
		t.Fatalf("解除: %+v %v", r, err)
	}
	if len(m.Active()) != 0 {
		t.Fatal("解除后不应下发")
	}
	if p, ac := m.Counts(); p != 0 || ac != 0 {
		t.Fatalf("计数: %d %d", p, ac)
	}
}

func TestAllowSelfApprove(t *testing.T) {
	m := newManager(t, config.BlockConfig{AllowSelfApprove: true})
	a, _ := m.Request("203.0.113.1", "x", 0, 0, "root")
	if _, err := m.Approve(a.ID, "root"); err != nil {
		t.Fatal(err)
	}
}

func TestWebhook(t *testing.T) {
	got := make(chan event, 4)
	var auth string
	fails := 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if fails > 0 {
			fails--
			w.WriteHeader(500)
			return
		}
		var e event
		json.NewDecoder(r.Body).Decode(&e)
		got <- e
	}))
	defer srv.Close()
	m, err := New(Options{Cfg: config.BlockConfig{Enabled: true, WebhookURL: srv.URL}, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	a, _ := m.Request("203.0.113.1", "x", 0, 0, "ana")
	m.Approve(a.ID, "root")
	select {
	case e := <-got:
		if e.Action != "block" || e.IP != "203.0.113.1" || auth != "Bearer tok" {
			t.Fatalf("推送: %+v %s", e, auth)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("失败后应重试并送达")
	}
	m.Release(a.ID, "root", "")
	select {
	case e := <-got:
		if e.Action != "unblock" {
			t.Fatalf("解除推送: %+v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("没有收到解除推送")
	}
}
