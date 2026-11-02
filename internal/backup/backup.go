// Package backup 备份与恢复状态目录：事件与处置记录、账号、配置、学习结果和审计链。
//
// 备份是带清单的 tar.gz，清单记录每个文件的 SHA-256；恢复时先解压到临时目录并校验，全部通过后才替换文件，
// 中途失败不会留下一半新一半旧的状态。备份里有密码哈希和模型密钥，文件权限固定为 0600。
package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	manifestName = "netsa-backup.json"
	maxFileSize  = 64 << 30 // 恢复时单个文件的上限，防止损坏或恶意的备份写满磁盘
	restoreTmp   = ".restore-tmp"
)

// Manifest 是备份清单。
type Manifest struct {
	Version string            `json:"version"` // 生成备份的程序版本
	Created time.Time         `json:"created"`
	RawLog  bool              `json:"rawlog"`
	Files   map[string]string `json:"files"` // 相对路径 → SHA-256
}

// Options 是备份参数。
type Options struct {
	Version string
	// RawLog 同时备份原始日志（可能很大，默认不包含）
	RawLog bool
}

func skip(rel string, raw bool) bool {
	base := path.Base(rel)
	if strings.HasSuffix(base, ".tmp") || strings.HasPrefix(rel, restoreTmp) || strings.HasPrefix(rel, "backups/") {
		return true
	}
	return !raw && (rel == "rawlog" || strings.HasPrefix(rel, "rawlog/"))
}

// Create 把状态目录写入 w。状态文件都是原子替换的，可以在服务运行时备份。
func Create(w io.Writer, dir string, opt Options) (*Manifest, error) {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	m := &Manifest{Version: opt.Version, Created: time.Now(), RawLog: opt.RawLog, Files: map[string]string{}}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) { // 备份期间被轮转的文件
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if skip(rel, opt.RawLog) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		sum, err := addFile(tw, p, rel)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("备份 %s: %w", rel, err)
		}
		m.Files[rel] = sum
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("状态目录 %s 没有可备份的文件", dir)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(data)), ModTime: m.Created, Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return m, gz.Close()
}

func addFile(tw *tar.Writer, p, rel string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	// 追加写入的文件（审计链、预写日志）只备份打开时的长度，保证头部声明的大小与内容一致
	if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tw, h), f, st.Size()); err != nil && !(errors.Is(err, io.EOF) && st.Size() == 0) {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CreateFile 把备份写入文件（先写临时文件再改名，权限 0600）。
func CreateFile(file, dir string, opt Options) (*Manifest, error) {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return nil, err
	}
	tmp := file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	m, err := Create(f, dir, opt)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return m, os.Rename(tmp, file)
}

// safeRel 校验备份中的路径：只接受目录内的相对路径。
func safeRel(name string) (string, error) {
	if name == "" || strings.Contains(name, "\\") || path.IsAbs(name) || filepath.IsAbs(name) || strings.Contains(name, ":") {
		return "", fmt.Errorf("备份中有不安全的路径: %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != name {
		return "", fmt.Errorf("备份中有不安全的路径: %q", name)
	}
	return clean, nil
}

// Restore 把备份恢复到状态目录。服务必须已经停止，否则退出时的快照会覆盖恢复的内容。
// 目录中已有文件时必须指定 force；备份中没有的旧文件保持不变。
func Restore(r io.Reader, dir string, force bool) (*Manifest, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if !force {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		if len(entries) > 0 {
			return nil, fmt.Errorf("状态目录 %s 不是空的：确认要覆盖时请加 -force，并先停止服务", dir)
		}
	}
	tmp := filepath.Join(dir, restoreTmp)
	if err := os.RemoveAll(tmp); err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	m, err := extract(r, tmp)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(m.Files))
	for rel := range m.Files {
		names = append(names, rel)
	}
	sort.Strings(names)
	for _, rel := range names {
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return m, err
		}
		if err := os.Rename(filepath.Join(tmp, filepath.FromSlash(rel)), dst); err != nil {
			return m, fmt.Errorf("恢复 %s: %w", rel, err)
		}
	}
	return m, nil
}

// extract 解压到临时目录并校验清单：多出、缺少或内容不符的文件都拒绝。
func extract(r io.Reader, dir string) (*Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("不是有效的备份文件: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	sums := map[string]string{}
	var m *Manifest
	for {
		hd, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("备份文件已损坏: %w", err)
		}
		if hd.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("备份中有不支持的条目: %q", hd.Name)
		}
		if hd.Name == manifestName {
			m = &Manifest{}
			if err := json.NewDecoder(io.LimitReader(tr, 64<<20)).Decode(m); err != nil {
				return nil, fmt.Errorf("备份清单已损坏: %w", err)
			}
			continue
		}
		rel, err := safeRel(hd.Name)
		if err != nil {
			return nil, err
		}
		if hd.Size < 0 || hd.Size > maxFileSize {
			return nil, fmt.Errorf("备份中的文件 %s 大小异常", rel)
		}
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(tr, hd.Size))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, err
		}
		sums[rel] = hex.EncodeToString(h.Sum(nil))
	}
	if m == nil {
		return nil, errors.New("备份中没有清单，不是 netsa 生成的备份")
	}
	if len(m.Files) != len(sums) {
		return nil, fmt.Errorf("备份不完整：清单有 %d 个文件，实际 %d 个", len(m.Files), len(sums))
	}
	for rel, want := range m.Files {
		if _, err := safeRel(rel); err != nil {
			return nil, err
		}
		if sums[rel] != want {
			return nil, fmt.Errorf("文件 %s 校验失败，备份可能已损坏或被改动", rel)
		}
	}
	return m, nil
}

// Rotate 只保留目录中最新的 keep 个定时备份。
func Rotate(dir string, keep int) error {
	if keep <= 0 {
		return nil
	}
	entries, err := filepath.Glob(filepath.Join(dir, "netsa-*.tar.gz"))
	if err != nil {
		return err
	}
	sort.Strings(entries) // 文件名含时间，字典序即时间序
	for len(entries) > keep {
		if err := os.Remove(entries[0]); err != nil {
			return err
		}
		entries = entries[1:]
	}
	return nil
}

// ScheduledName 返回定时备份的文件名。
func ScheduledName(now time.Time) string {
	return "netsa-" + now.Format("20060102-150405") + ".tar.gz"
}
