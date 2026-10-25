package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// 双因素认证使用 TOTP（RFC 6238）：HMAC-SHA1、6 位数字、30 秒一个时间片，兼容 Google Authenticator、
// Microsoft Authenticator、企业微信 / 钉钉 / 飞书内置的身份验证器等应用。

const (
	totpDigits = 6
	totpPeriod = 30
	totpSkew   = 1 // 允许前后各 1 个时间片的时钟偏差
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret 生成 160 位随机密钥（Base32 编码）。
func NewTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return b32.EncodeToString(b)
}

// hotp 计算 RFC 4226 的一次性口令。
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

func decodeSecret(secret string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
}

// verifyTOTP 校验验证码，返回匹配的时间片。last 为该账号上次成功使用的时间片：
// 同一个时间片（及更早的）验证码不能重复使用，防止验证码被截获后重放。
func verifyTOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := decodeSecret(secret)
	if err != nil || len(key) == 0 {
		return 0, false
	}
	step := now.Unix() / totpPeriod
	for d := -totpSkew; d <= totpSkew; d++ {
		s := step + int64(d)
		if s <= last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(s), totpDigits)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// OTPAuthURL 返回身份验证器应用可识别的 otpauth:// 地址（手机上点击即可添加）。
func OTPAuthURL(issuer, user, secret string) string {
	label := url.PathEscape(issuer + ":" + user)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// newRecoveryCodes 生成 8 个一次性恢复码（手机丢失时用于登录），返回明文与哈希。
func newRecoveryCodes() (plain, hashes []string) {
	for i := 0; i < 8; i++ {
		b := make([]byte, 5)
		rand.Read(b)
		c := strings.ToLower(b32.EncodeToString(b)) // 8 个字符
		c = c[:4] + "-" + c[4:]
		plain = append(plain, c)
		hashes = append(hashes, hashRecovery(c))
	}
	return
}

func hashRecovery(code string) string {
	code = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte("netsa-recovery:" + code))
	return hex.EncodeToString(sum[:])
}
