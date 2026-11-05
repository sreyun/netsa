package intel

import (
	"regexp"
	"strings"
)

// 指纹与文件哈希情报（P3）：TLS 客户端指纹 JA3（32 位十六进制 MD5）、JA4（t13d1516h2_8daaf6152771_02713d6af862），
// 以及文件的 MD5 / SHA1 / SHA256。abuse.ch SSLBL 的 ja3_fingerprints.csv、MalwareBazaar 的哈希列表可以直接作为
// 本地情报文件或在线情报源（CSV 取每行第一列）。条目可以带 ja3: / ja4: 前缀。

var reJA4 = regexp.MustCompile(`^[tqd][0-9s]{2}[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// fingerKey 规范化指纹或哈希条目，不是指纹或哈希时返回空串。
func fingerKey(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if k, ok := strings.CutPrefix(v, "ja3:"); ok {
		v = k
	} else if k, ok := strings.CutPrefix(v, "ja4:"); ok {
		v = k
	}
	switch len(v) {
	case 32, 40, 64:
		if isHex(v) {
			return v
		}
	}
	if reJA4.MatchString(v) {
		return v
	}
	return ""
}

// MatchFinger 返回标记了该 TLS 客户端指纹（ja3:… / ja4:…）的情报名称；只有协议与加密套件的弱指纹不匹配。
func (db *DB) MatchFinger(f string) []string {
	if db == nil || !strings.HasPrefix(f, "ja3:") && !strings.HasPrefix(f, "ja4:") {
		return nil
	}
	return db.matchKey(fingerKey(f))
}

// MatchHash 返回标记了任一文件哈希的情报名称。
func (db *DB) MatchHash(hashes ...string) []string {
	if db == nil {
		return nil
	}
	for _, h := range hashes {
		if k := fingerKey(h); k != "" && !strings.Contains(k, "_") {
			if names := db.matchKey(k); len(names) > 0 {
				return names
			}
		}
	}
	return nil
}

func (db *DB) matchKey(k string) []string {
	if k == "" {
		return nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	var hits []string
	for _, l := range db.lists {
		if _, ok := l.fingers[k]; ok {
			hits = append(hits, l.name)
		}
	}
	return hits
}
