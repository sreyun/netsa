package exposure

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"netsa/internal/geo"
)

// 自动识别的对外服务持久化。此前只保存在内存中，重启后清单为空，要等再次出现带会话证据的日志才会重新识别：
// 在此期间开启了 exposure.enabled 时，只输出策略日志的设备上发往这些服务的探测会被当作「未发布端口」降级，
// 攻击面中「对外开放」的标注也会缺失。

// learnedTTL 为恢复自动识别结果的时限：超过该时间没有再出现会话证据的服务不再恢复（服务可能已下线）。
const learnedTTL = 30 * 24 * time.Hour

type learnedFile struct {
	Learned []LearnedService `json:"learned"`
}

// SetPath 设置自动识别结果的保存位置，并恢复上次保存的结果（文件不存在时忽略）。只在启动时调用一次。
func (m *Manager) SetPath(path string, now time.Time) error {
	if m == nil || path == "" {
		return nil
	}
	m.learnMu.Lock()
	defer m.learnMu.Unlock()
	m.path = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f learnedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	for _, l := range f.Learned {
		ip := normIP(l.PublicIP)
		if ip == "" || geo.IsPrivate(ip) || l.PublicPort <= 0 || l.PublicPort > 65535 || now.Sub(l.LastSeen) > learnedTTL {
			continue
		}
		if len(m.learned) >= maxLearned {
			break
		}
		proto := normProto(l.Proto)
		m.learned[key(ip, l.PublicPort, proto)] = &learnedSvc{ip: ip, port: l.PublicPort, proto: proto, reason: l.Reason,
			hits: l.Hits, first: l.FirstSeen, last: l.LastSeen}
	}
	return nil
}

// Flush 在自动识别结果有变化时写入文件（先写临时文件再原子替换）。
func (m *Manager) Flush() error {
	if m == nil || m.path == "" || !m.learnDirty.Swap(false) {
		return nil
	}
	err := writeLearned(m.path, learnedFile{Learned: m.Learned()})
	if err != nil {
		m.learnDirty.Store(true) // 下次重试
		return fmt.Errorf("保存自动识别的对外服务失败: %w", err)
	}
	return nil
}

func writeLearned(path string, f learnedFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
