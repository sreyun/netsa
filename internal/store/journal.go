package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// 处置记录预写日志：快照默认每分钟保存一次，进程异常退出（断电、kill -9、OOM）时最近一分钟的数据会丢。
// 告警可以从日志重新分析，分析员的处置结论却无处恢复。因此每次人工或模型改动事件时，先把事件完整追加到
// 日志文件并落盘；启动时在快照之上重放，快照保存成功后丢弃已经包含在快照里的部分。

const maxJournalLine = 8 << 20 // 单个事件的上限（处置记录最多 200 条，正常远小于该值）

type journalEntry struct {
	Incident *Incident `json:"incident"`
}

// OpenIncidentJournal 重放并打开处置记录预写日志（在 Load 之后调用）。path 为空表示不启用。
func (s *Store) OpenIncidentJournal(path string) (replayed int, err error) {
	if path == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if replayed, err = s.replayJournalLocked(path); err != nil {
		return replayed, err
	}
	// 全新安装时状态目录还不存在（第一次保存快照时才创建）
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return replayed, err
	}
	// 权限与快照一致
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return replayed, err
	}
	s.journal, s.journalPath = f, path
	return replayed, nil
}

// replayJournalLocked 把日志中比快照新的事件写回内存。末尾写了一半的行（写入时断电）直接忽略。
func (s *Store) replayJournalLocked(path string) (int, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxJournalLine)
	for sc.Scan() {
		var e journalEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil || e.Incident == nil || e.Incident.ID == 0 {
			log.Printf("[store] 忽略处置记录日志中无法解析的一行（可能是写入时断电）")
			continue
		}
		inc := e.Incident
		if cur := s.incidents[inc.ID]; cur != nil && !inc.Updated.After(cur.Updated) {
			continue
		}
		inc.ensureMaps()
		s.incidents[inc.ID] = inc
		if inc.ID > s.nextInc {
			s.nextInc = inc.ID
		}
		if cur := s.incidents[s.incByKey[inc.Key]]; cur == nil || cur.ID <= inc.ID {
			s.incByKey[inc.Key] = inc.ID
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return n, fmt.Errorf("读取处置记录日志 %s: %w", path, err)
	}
	return n, nil
}

// journalLocked 把事件追加到日志并落盘（调用方持写锁）。写失败只告警：不能因为磁盘问题拒绝分析员的处置。
func (s *Store) journalLocked(list ...*Incident) {
	if s.journal == nil || len(list) == 0 {
		return
	}
	buf := make([]byte, 0, 4096)
	for _, inc := range list {
		line, err := json.Marshal(journalEntry{Incident: inc})
		if err != nil || len(line) >= maxJournalLine {
			log.Printf("[store] 事件 #%d 写入处置记录日志失败: %v", inc.ID, err)
			continue
		}
		buf = append(append(buf, line...), '\n')
	}
	if _, err := s.journal.Write(buf); err != nil {
		log.Printf("[store] 写入处置记录日志失败: %v", err)
		return
	}
	if err := s.journal.Sync(); err != nil {
		log.Printf("[store] 处置记录日志落盘失败: %v", err)
	}
}

// journalMark 返回保存快照前的日志长度：之后写入的内容可能不在快照里，不能丢弃。
func (s *Store) journalMark() int64 {
	s.mu.Lock()
	defer s.mu.unlockClean() // 只读日志文件的长度，不修改快照中的数据
	if s.journal == nil {
		return -1
	}
	st, err := s.journal.Stat()
	if err != nil {
		return -1
	}
	return st.Size()
}

// compactJournal 在快照保存成功后丢弃 mark 之前的内容。
func (s *Store) compactJournal(mark int64) error {
	if mark <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.unlockClean() // 只整理日志文件，不修改快照中的数据
	if s.journal == nil {
		return nil
	}
	tmp := s.journalPath + ".tmp"
	src, err := os.Open(s.journalPath)
	if err != nil {
		return err
	}
	defer src.Close()
	if _, err := src.Seek(mark, io.SeekStart); err != nil {
		return err
	}
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(dst, src); err == nil {
		err = dst.Sync()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	src.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	// Windows 上不能替换打开中的文件：先关闭，失败时重新打开原文件继续使用
	s.journal.Close()
	renameErr := os.Rename(tmp, s.journalPath)
	f, err := os.OpenFile(s.journalPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.journal = nil
		return err
	}
	s.journal = f
	return renameErr
}

// CloseJournal 关闭处置记录日志。
func (s *Store) CloseJournal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal != nil {
		s.journal.Close()
		s.journal = nil
	}
}
