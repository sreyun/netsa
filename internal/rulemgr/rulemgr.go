// Package rulemgr 管理页面上维护的自定义规则与签名规则包，变更后热更新检测引擎，无需重启。
package rulemgr

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"netsa/internal/detect"
)

const (
	maxRules   = 2000
	maxPattern = 4096
	sourceUI   = "ui"
)

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Item 是一条托管的规则。
type Item struct {
	detect.Rule
	Source  string    `json:"source"` // ui、sigma 或 pack:名称
	Updated time.Time `json:"updated"`
	By      string    `json:"by,omitempty"`
}

// PackState 是已安装的规则包。
type PackState struct {
	Name    string    `json:"name"`
	Serial  int64     `json:"serial"`
	Rules   int       `json:"rules"`
	KeyID   string    `json:"key_id"`
	Updated time.Time `json:"updated"`
	By      string    `json:"by,omitempty"`
}

type state struct {
	Rules []Item      `json:"rules"`
	Packs []PackState `json:"packs,omitempty"`
}

// Options 是规则管理的参数。
type Options struct {
	Path      string
	RulesFile string   // detect.rules_file
	MinBytes  int64    // detect.success_min_bytes
	Keys      []string // 允许的规则包公钥（base64）
	// OnChange 在规则变更后接收新的引擎
	OnChange func(*detect.Engine)
}

// Manager 管理规则。所有修改先构建新引擎，成功才保存和切换：一条错误的规则不会影响正在运行的检测。
type Manager struct {
	opt    Options
	keys   map[string]ed25519.PublicKey
	mu     sync.Mutex
	st     state
	eng    *detect.Engine
	shadow *detect.ShadowStats // 影子运行规则的命中，在引擎重建之间保留
}

// New 加载规则并构建引擎。已保存的规则无法加载时报错，而不是静默丢弃客户配置的检测能力。
func New(opt Options) (*Manager, error) {
	m := &Manager{opt: opt, keys: map[string]ed25519.PublicKey{}, shadow: detect.NewShadowStats()}
	for _, k := range opt.Keys {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("规则包公钥无效: %q", k)
		}
		m.keys[KeyID(raw)] = ed25519.PublicKey(raw)
	}
	if opt.Path != "" {
		data, err := os.ReadFile(opt.Path)
		if err == nil {
			if err := json.Unmarshal(data, &m.st); err != nil {
				return nil, fmt.Errorf("读取规则文件 %s: %w", opt.Path, err)
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	eng, err := m.build(m.st.Rules)
	if err != nil {
		return nil, err
	}
	m.eng = eng
	return m, nil
}

// KeyID 返回公钥的短标识。
func KeyID(pub []byte) string {
	if len(pub) < 6 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(pub[:6])
}

func (m *Manager) build(items []Item) (*detect.Engine, error) {
	rules := make([]detect.Rule, len(items))
	for i, it := range items {
		rules[i] = it.Rule
	}
	eng, err := detect.NewEngineWith(m.opt.RulesFile, rules, m.opt.MinBytes)
	if err != nil {
		return nil, err
	}
	eng.SetShadow(m.shadow)
	return eng, nil
}

// Shadow 返回影子运行规则的命中统计。
func (m *Manager) Shadow() map[string]detect.ShadowStat { return m.shadow.Snapshot() }

// Engine 返回当前引擎。
func (m *Manager) Engine() *detect.Engine {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eng
}

// List 返回托管的规则和规则包。
func (m *Manager) List() ([]Item, []PackState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Item(nil), m.st.Rules...), append([]PackState(nil), m.st.Packs...)
}

func (m *Manager) commitLocked(items []Item, packs []PackState) error {
	if len(items) > maxRules {
		return fmt.Errorf("托管规则最多 %d 条", maxRules)
	}
	defer func() {
		var ids []string
		for _, it := range m.st.Rules {
			if it.Shadow {
				ids = append(ids, it.ID)
			}
		}
		m.shadow.Keep(ids) // 删除或转为正式的规则不再保留影子统计
	}()
	eng, err := m.build(items)
	if err != nil {
		return err
	}
	next := state{Rules: items, Packs: packs}
	if m.opt.Path != "" {
		data, err := json.MarshalIndent(next, "", " ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(m.opt.Path), 0o700); err != nil {
			return err
		}
		tmp := m.opt.Path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, m.opt.Path); err != nil {
			return err
		}
	}
	m.st, m.eng = next, eng
	if m.opt.OnChange != nil {
		m.opt.OnChange(eng)
	}
	return nil
}

func checkRule(r *detect.Rule) error {
	r.ID = strings.TrimSpace(r.ID)
	if !idRe.MatchString(r.ID) {
		return errors.New("规则 ID 只能包含字母、数字、下划线、点和短横线，最长 64 个字符")
	}
	if strings.TrimSpace(r.Pattern) == "" {
		return errors.New("请填写匹配表达式")
	}
	if len(r.Pattern) > maxPattern {
		return fmt.Errorf("匹配表达式不能超过 %d 个字符", maxPattern)
	}
	if len([]rune(r.Name)) > 100 || len([]rune(r.Category)) > 30 {
		return errors.New("规则名称或分类过长")
	}
	// 与检测时的默认值保持一致，页面上显示的就是实际生效的值
	if r.Name == "" {
		r.Name = r.ID
	}
	if r.Category == "" {
		r.Category = "自定义规则"
	}
	if r.Target == "" {
		r.Target = "uri"
	}
	return nil
}

// Upsert 新增或修改一条页面维护的规则。规则包里的规则只能通过更新规则包修改。
func (m *Manager) Upsert(r detect.Rule, source, user string) (*Item, error) {
	if err := checkRule(&r); err != nil {
		return nil, err
	}
	if source == "" {
		source = sourceUI
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	items := append([]Item(nil), m.st.Rules...)
	it := Item{Rule: r, Source: source, Updated: time.Now(), By: user}
	found, changed := false, false
	for i := range items {
		if items[i].ID == r.ID {
			if strings.HasPrefix(items[i].Source, "pack:") {
				return nil, fmt.Errorf("规则 %s 来自规则包，请更新规则包", r.ID)
			}
			changed = !sameMatch(items[i].Rule, r)
			items[i] = it
			found = true
		}
	}
	if !found {
		items = append(items, it)
	}
	if err := m.commitLocked(items, m.st.Packs); err != nil {
		return nil, err
	}
	if changed {
		m.shadow.Reset(r.ID) // 匹配条件变了：此前的影子命中不再代表这条规则的效果
	}
	return &it, nil
}

// sameMatch 判断两条规则的匹配条件是否相同（名称、等级等展示字段的修改不影响命中）。
func sameMatch(a, b detect.Rule) bool {
	return a.Pattern == b.Pattern && a.Target == b.Target && a.OnlyFailed == b.OnlyFailed && slices.Equal(a.Methods, b.Methods)
}

// Delete 删除一条页面维护的规则。
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]Item, 0, len(m.st.Rules))
	found := false
	for _, it := range m.st.Rules {
		if it.ID == id {
			if strings.HasPrefix(it.Source, "pack:") {
				return fmt.Errorf("规则 %s 来自规则包，请卸载规则包", id)
			}
			found = true
			continue
		}
		items = append(items, it)
	}
	if !found {
		return errors.New("规则不存在")
	}
	return m.commitLocked(items, m.st.Packs)
}

// TestResult 是规则试运行的结果。
type TestResult struct {
	Matched  bool   `json:"matched"`
	Evidence string `json:"evidence,omitempty"`
}

// Test 用样本试运行一条规则（不保存）：文本按检测时相同的方式解码和归一化。
func Test(r detect.Rule, sample string) (*TestResult, error) {
	if r.ID == "" {
		r.ID = "test"
	}
	if err := checkRule(&r); err != nil {
		return nil, err
	}
	ok, ev, err := detect.TestRule(r, sample)
	if err != nil {
		return nil, err
	}
	return &TestResult{Matched: ok, Evidence: ev}, nil
}

// Pack 是签名的规则包。Serial 必须递增，防止安装旧版本回滚掉新规则。
type Pack struct {
	Name      string        `json:"name"`
	Serial    int64         `json:"serial"`
	Rules     []detect.Rule `json:"rules"`
	KeyID     string        `json:"key_id"`
	Signature string        `json:"signature"`
}

func (p Pack) signedBytes() ([]byte, error) {
	return json.Marshal(struct {
		Name   string        `json:"name"`
		Serial int64         `json:"serial"`
		Rules  []detect.Rule `json:"rules"`
	}{p.Name, p.Serial, p.Rules})
}

// Sign 用私钥签名规则包。
func Sign(p *Pack, priv ed25519.PrivateKey) error {
	data, err := p.signedBytes()
	if err != nil {
		return err
	}
	p.KeyID = KeyID(priv.Public().(ed25519.PublicKey))
	p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
	return nil
}

var packNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// InstallPack 校验签名后安装规则包，替换同名规则包的全部规则。任何一条规则无效时整个规则包都不生效。
func (m *Manager) InstallPack(p Pack, user string) (*PackState, error) {
	if !packNameRe.MatchString(p.Name) {
		return nil, errors.New("规则包名称无效")
	}
	if p.Serial <= 0 || len(p.Rules) == 0 {
		return nil, errors.New("规则包缺少序号或规则")
	}
	key := m.keys[p.KeyID]
	if key == nil {
		return nil, errors.New("规则包的签名密钥不在信任列表中（detect.rule_pack_keys）")
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return nil, errors.New("规则包的签名格式错误")
	}
	data, err := p.signedBytes()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, data, sig) {
		return nil, errors.New("规则包签名校验失败，内容可能被改动")
	}
	source := "pack:" + p.Name
	m.mu.Lock()
	defer m.mu.Unlock()
	packs := make([]PackState, 0, len(m.st.Packs)+1)
	for _, ps := range m.st.Packs {
		if ps.Name == p.Name {
			if p.Serial <= ps.Serial {
				return nil, fmt.Errorf("规则包序号 %d 不高于已安装的 %d，拒绝回滚", p.Serial, ps.Serial)
			}
			continue
		}
		packs = append(packs, ps)
	}
	items := make([]Item, 0, len(m.st.Rules)+len(p.Rules))
	taken := map[string]string{}
	for _, it := range m.st.Rules {
		if it.Source != source {
			items = append(items, it)
			taken[it.ID] = it.Source
		}
	}
	now := time.Now()
	for _, r := range p.Rules {
		if err := checkRule(&r); err != nil {
			return nil, fmt.Errorf("规则 %q: %w", r.ID, err)
		}
		if src, dup := taken[r.ID]; dup {
			return nil, fmt.Errorf("规则 %s 与来源 %s 的规则冲突", r.ID, src)
		}
		taken[r.ID] = source
		items = append(items, Item{Rule: r, Source: source, Updated: now, By: user})
	}
	st := PackState{Name: p.Name, Serial: p.Serial, Rules: len(p.Rules), KeyID: p.KeyID, Updated: now, By: user}
	packs = append(packs, st)
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	if err := m.commitLocked(items, packs); err != nil {
		return nil, err
	}
	return &st, nil
}

// UninstallPack 卸载规则包。
func (m *Manager) UninstallPack(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	packs := make([]PackState, 0, len(m.st.Packs))
	found := false
	for _, ps := range m.st.Packs {
		if ps.Name == name {
			found = true
			continue
		}
		packs = append(packs, ps)
	}
	if !found {
		return errors.New("规则包不存在")
	}
	source := "pack:" + name
	items := make([]Item, 0, len(m.st.Rules))
	for _, it := range m.st.Rules {
		if it.Source != source {
			items = append(items, it)
		}
	}
	return m.commitLocked(items, packs)
}

// ImportRules 批量导入规则（Sigma 转换的结果）：要么全部生效，要么都不生效。
func (m *Manager) ImportRules(rules []detect.Rule, source, user string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := append([]Item(nil), m.st.Rules...)
	index := map[string]int{}
	for i, it := range items {
		index[it.ID] = i
	}
	now := time.Now()
	for _, r := range rules {
		if err := checkRule(&r); err != nil {
			return 0, fmt.Errorf("规则 %q: %w", r.ID, err)
		}
		it := Item{Rule: r, Source: source, Updated: now, By: user}
		if i, ok := index[r.ID]; ok {
			if strings.HasPrefix(items[i].Source, "pack:") {
				return 0, fmt.Errorf("规则 %s 来自规则包", r.ID)
			}
			items[i] = it
			continue
		}
		index[r.ID] = len(items)
		items = append(items, it)
	}
	if err := m.commitLocked(items, m.st.Packs); err != nil {
		return 0, err
	}
	return len(rules), nil
}
