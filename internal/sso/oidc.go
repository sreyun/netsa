package sso

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"netsa/internal/config"
)

const (
	oidcClockSkew = time.Minute
	oidcStateTTL  = 10 * time.Minute
	maxOIDCStates = 10000
)

type oidcDiscovery struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURI  string `json:"jwks_uri"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type oidcState struct {
	nonce, verifier string
	expires         time.Time
}

// OIDC 实现授权码流程（带 PKCE），自行校验 ID Token 的签名与声明。
type OIDC struct {
	cfg    config.OIDCConfig
	secret string
	client *http.Client

	mu      sync.Mutex
	disc    *oidcDiscovery
	keys    map[string]crypto.PublicKey
	keysAt  time.Time
	states  map[string]oidcState
	nowFunc func() time.Time
}

// NewOIDC 创建 OIDC 客户端；未配置时返回 nil。发现文档在首次登录时获取，身份提供方暂时不可用不影响启动。
func NewOIDC(cfg config.OIDCConfig) *OIDC {
	if cfg.Issuer == "" {
		return nil
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "groups"
	}
	o := &OIDC{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}, states: map[string]oidcState{}, nowFunc: time.Now}
	if cfg.ClientSecretEnv != "" {
		o.secret = os.Getenv(cfg.ClientSecretEnv)
	}
	return o
}

// DisplayName 返回登录页按钮上的名称。
func (o *OIDC) DisplayName() string {
	if o.cfg.DisplayName != "" {
		return o.cfg.DisplayName
	}
	return "单点登录"
}

func (o *OIDC) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s 返回 %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func (o *OIDC) discovery(ctx context.Context) (*oidcDiscovery, error) {
	o.mu.Lock()
	d := o.disc
	o.mu.Unlock()
	if d != nil {
		return d, nil
	}
	var doc oidcDiscovery
	if err := o.getJSON(ctx, strings.TrimRight(o.cfg.Issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("获取 OIDC 发现文档: %w", err)
	}
	// 发现文档声明的 issuer 必须与配置一致，防止被重定向到其他身份提供方
	if strings.TrimRight(doc.Issuer, "/") != strings.TrimRight(o.cfg.Issuer, "/") {
		return nil, fmt.Errorf("OIDC 发现文档的 issuer %q 与配置不一致", doc.Issuer)
	}
	if doc.AuthURL == "" || doc.TokenURL == "" || doc.JWKSURI == "" {
		return nil, errors.New("OIDC 发现文档缺少必要的地址")
	}
	o.mu.Lock()
	o.disc = &doc
	o.mu.Unlock()
	return &doc, nil
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Start 生成跳转到身份提供方的地址，返回 state（由调用方写入浏览器 Cookie，回调时比对）。
func (o *OIDC) Start(ctx context.Context) (redirect, state string, err error) {
	d, err := o.discovery(ctx)
	if err != nil {
		return "", "", err
	}
	state = randToken()
	nonce, verifier := randToken(), randToken()
	now := o.nowFunc()
	o.mu.Lock()
	for k, v := range o.states {
		if now.After(v.expires) {
			delete(o.states, k)
		}
	}
	if len(o.states) >= maxOIDCStates {
		o.mu.Unlock()
		return "", "", errors.New("登录请求过多，请稍后重试")
	}
	o.states[state] = oidcState{nonce: nonce, verifier: verifier, expires: now.Add(oidcStateTTL)}
	o.mu.Unlock()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {o.cfg.ClientID}, "redirect_uri": {o.cfg.RedirectURL},
		"scope": {strings.Join(o.cfg.Scopes, " ")}, "state": {state}, "nonce": {nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(d.AuthURL, "?") {
		sep = "&"
	}
	return d.AuthURL + sep + q.Encode(), state, nil
}

// Identity 是通过校验的外部身份。
type Identity struct {
	Username string
	Role     string
}

// Finish 用授权码换取并校验 ID Token。state 一次性使用，防止重放。
func (o *OIDC) Finish(ctx context.Context, state, code string) (*Identity, error) {
	o.mu.Lock()
	st, ok := o.states[state]
	delete(o.states, state)
	o.mu.Unlock()
	if !ok || o.nowFunc().After(st.expires) {
		return nil, errors.New("登录请求已过期，请重新登录")
	}
	d, err := o.discovery(ctx)
	if err != nil {
		return nil, err
	}
	token, err := o.exchange(ctx, d, code, st.verifier)
	if err != nil {
		return nil, err
	}
	claims, err := o.verifyIDToken(ctx, d, token, st.nonce)
	if err != nil {
		return nil, err
	}
	return o.identity(claims)
}

func (o *OIDC) exchange(ctx context.Context, d *oidcDiscovery, code, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {o.cfg.RedirectURL}, "client_id": {o.cfg.ClientID}, "code_verifier": {verifier}}
	if o.secret != "" {
		form.Set("client_secret", o.secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("换取令牌: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("换取令牌: 响应无法解析: %w", err)
	}
	if resp.StatusCode != 200 || out.IDToken == "" {
		return "", fmt.Errorf("换取令牌失败: %d %s", resp.StatusCode, out.Error)
	}
	return out.IDToken, nil
}

func (o *OIDC) publicKey(ctx context.Context, d *oidcDiscovery, kid string) (crypto.PublicKey, error) {
	o.mu.Lock()
	k, ok := o.keys[kid]
	fresh := o.nowFunc().Sub(o.keysAt) < time.Minute
	o.mu.Unlock()
	if ok {
		return k, nil
	}
	if fresh { // 未知的 kid：最多每分钟刷新一次，防止伪造的令牌反复触发请求
		return nil, errors.New("ID Token 使用了未知的签名密钥")
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := o.getJSON(ctx, d.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("获取签名密钥: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, j := range set.Keys {
		if pk, err := j.publicKey(); err == nil {
			keys[j.Kid] = pk
		}
	}
	o.mu.Lock()
	o.keys, o.keysAt = keys, o.nowFunc()
	o.mu.Unlock()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("ID Token 使用了未知的签名密钥")
}

func (j jwk) publicKey() (crypto.PublicKey, error) {
	dec := base64.RawURLEncoding
	switch j.Kty {
	case "RSA":
		n, err1 := dec.DecodeString(j.N)
		e, err2 := dec.DecodeString(j.E)
		if err1 != nil || err2 != nil {
			return nil, errors.New("RSA 密钥格式错误")
		}
		exp := new(big.Int).SetBytes(e)
		if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 {
			return nil, errors.New("RSA 公钥指数无效")
		}
		pk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}
		if pk.N.BitLen() < 2048 {
			return nil, errors.New("RSA 密钥过短")
		}
		return pk, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, errors.New("只支持 P-256")
		}
		x, err1 := dec.DecodeString(j.X)
		y, err2 := dec.DecodeString(j.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("EC 密钥格式错误")
		}
		if len(x) != 32 || len(y) != 32 { // RFC 7518 6.2.1.2：P-256 的坐标固定 32 字节
			return nil, errors.New("EC 密钥长度错误")
		}
		// 按未压缩点解析，同时校验点在曲线上（取代已弃用的 IsOnCurve）
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, errors.New("EC 公钥不在曲线上")
		}
		return pk, nil
	}
	return nil, fmt.Errorf("不支持的密钥类型 %q", j.Kty)
}

// verifyIDToken 校验签名与声明。算法只接受 RS256 / ES256，并且必须与密钥类型匹配：
// 接受 none 或由令牌自己决定算法是 JWT 校验最常见的绕过方式。
func (o *OIDC) verifyIDToken(ctx context.Context, d *oidcDiscovery, token, nonce string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("ID Token 格式错误")
	}
	dec := base64.RawURLEncoding
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	raw, err := dec.DecodeString(parts[0])
	if err != nil || json.Unmarshal(raw, &hdr) != nil {
		return nil, errors.New("ID Token 头部无法解析")
	}
	sig, err := dec.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("ID Token 签名无法解析")
	}
	key, err := o.publicKey(ctx, d, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pk := key.(type) {
	case *rsa.PublicKey:
		if hdr.Alg != "RS256" || rsa.VerifyPKCS1v15(pk, crypto.SHA256, sum[:], sig) != nil {
			return nil, errors.New("ID Token 签名校验失败")
		}
	case *ecdsa.PublicKey:
		if hdr.Alg != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(pk, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("ID Token 签名校验失败")
		}
	default:
		return nil, errors.New("ID Token 使用了不支持的算法")
	}
	var claims map[string]any
	raw, err = dec.DecodeString(parts[1])
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		return nil, errors.New("ID Token 内容无法解析")
	}
	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != strings.TrimRight(o.cfg.Issuer, "/") {
		return nil, errors.New("ID Token 的签发者不匹配")
	}
	if !audMatches(claims["aud"], o.cfg.ClientID) {
		return nil, errors.New("ID Token 不是签发给本平台的")
	}
	if got, _ := claims["nonce"].(string); got == "" || got != nonce {
		return nil, errors.New("ID Token 的 nonce 不匹配")
	}
	now := o.nowFunc()
	exp, ok := claims["exp"].(float64)
	if !ok || now.After(time.Unix(int64(exp), 0).Add(oidcClockSkew)) {
		return nil, errors.New("ID Token 已过期")
	}
	if iat, ok := claims["iat"].(float64); ok && time.Unix(int64(iat), 0).After(now.Add(oidcClockSkew)) {
		return nil, errors.New("ID Token 的签发时间晚于当前时间，请检查时钟")
	}
	return claims, nil
}

func audMatches(aud any, client string) bool {
	switch v := aud.(type) {
	case string:
		return v == client
	case []any:
		for _, a := range v {
			if a == client {
				return true
			}
		}
	}
	return false
}

func (o *OIDC) identity(claims map[string]any) (*Identity, error) {
	names := []string{o.cfg.UsernameClaim, "preferred_username", "email"}
	var user string
	for _, n := range names {
		if n == "" {
			continue
		}
		if v, _ := claims[n].(string); v != "" {
			user = v
			break
		}
	}
	if user == "" {
		return nil, errors.New("ID Token 中没有用户名")
	}
	var groups []string
	switch v := claims[o.cfg.RoleClaim].(type) {
	case string:
		groups = []string{v}
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	role := MapRole(o.cfg.RoleMap, groups)
	if role == "" {
		return nil, fmt.Errorf("账号 %q: %w", clipName(user), deniedError(groups))
	}
	return &Identity{Username: user, Role: role}, nil
}

func clipName(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}
