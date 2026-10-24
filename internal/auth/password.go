// Package auth 实现大屏的账号登录：PBKDF2 密码哈希、签名会话令牌、登录失败锁定与登录审计。
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// pbkdf2Iter 为 PBKDF2-HMAC-SHA256 的迭代次数（OWASP 2023 建议值），测试中可调低。
var pbkdf2Iter = 600000

const hashPrefix = "pbkdf2-sha256"

// pbkdf2 实现 RFC 8018 PBKDF2（HMAC-SHA256），只依赖标准库。
func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	u := make([]byte, hLen)
	t := make([]byte, hLen)
	for b := 1; b <= blocks; b++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(b))
		prf.Write(buf)
		u = prf.Sum(u[:0])
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// HashPassword 生成密码哈希，格式：pbkdf2-sha256$迭代次数$盐$哈希（盐与哈希为 base64）。
func HashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key := pbkdf2([]byte(password), salt, pbkdf2Iter, 32)
	return fmt.Sprintf("%s$%d$%s$%s", hashPrefix, pbkdf2Iter, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// IsHash 判断字符串是否为 HashPassword 生成的哈希（配置文件中的密码可以是明文或哈希）。
func IsHash(s string) bool { return strings.HasPrefix(s, hashPrefix+"$") }

// dummyHash 用于账号不存在时同样执行一次哈希计算，避免通过响应时间判断账号是否存在（首次使用时生成）。
var dummyHash = sync.OnceValue(func() string { return HashPassword("netsa-dummy-password") })

// VerifyPassword 校验密码。stored 为哈希或（配置文件中的）明文；比较均为常数时间。
func VerifyPassword(stored, password string) bool {
	if !IsHash(stored) {
		// 明文：先各自取摘要再比较，长度不同也不泄露时间差异
		a, b := sha256.Sum256([]byte(stored)), sha256.Sum256([]byte(password))
		return stored != "" && subtle.ConstantTimeCompare(a[:], b[:]) == 1
	}
	parts := strings.Split(stored, "$")
	if len(parts) != 4 {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 || iter > 10000000 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := pbkdf2([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ErrWeakPassword 表示密码强度不足。
var ErrWeakPassword = errors.New("密码至少 8 位，且需包含字母、数字、符号中的至少两类")

// CheckStrength 校验密码强度：至少 8 位、包含两类以上字符、不能与用户名相同。
func CheckStrength(user, password string) error {
	if utf8.RuneCountInString(password) < 8 || len(password) > 128 {
		return ErrWeakPassword
	}
	var letter, digit, other bool
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			letter = true
		case unicode.IsDigit(r):
			digit = true
		case !unicode.IsSpace(r):
			other = true
		}
	}
	n := 0
	for _, b := range []bool{letter, digit, other} {
		if b {
			n++
		}
	}
	if n < 2 {
		return ErrWeakPassword
	}
	if strings.EqualFold(password, user) {
		return errors.New("密码不能与用户名相同")
	}
	return nil
}

// RandomPassword 生成随机初始密码（字母、数字与符号，避免易混淆字符）。
func RandomPassword() string {
	const letters = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"
	const digits = "23456789"
	const symbols = "@#%+=-"
	all := letters + digits + symbols
	b := make([]byte, 16)
	rand.Read(b)
	out := make([]byte, 16)
	for i := range b {
		out[i] = all[int(b[i])%len(all)]
	}
	// 保证三类字符都出现
	out[3] = digits[int(b[3])%len(digits)]
	out[8] = symbols[int(b[8])%len(symbols)]
	out[12] = letters[int(b[12])%len(letters)]
	return string(out)
}
