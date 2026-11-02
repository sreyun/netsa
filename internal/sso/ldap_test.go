package sso

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	"netsa/internal/config"
)

// fakeDirectory 是一个最小的 LDAP 服务：支持简单绑定和查找，用于验证客户端的行为。
type fakeDirectory struct {
	ln      net.Listener
	mu      sync.Mutex
	filters []string
	entries []string // 查找返回的 DN
	groups  []string
}

const (
	appBindRequest    = 0
	appBindResponse   = 1
	appUnbindRequest  = 2
	appSearchRequest  = 3
	appSearchEntry    = 4
	appSearchDone     = 5
	ldapResultSuccess = 0
	ldapInvalidCreds  = 49
)

func newDirectory(t *testing.T) *fakeDirectory {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDirectory{ln: ln, entries: []string{"uid=alice,ou=people,dc=x"}, groups: []string{"cn=soc,ou=groups,dc=x"}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(c)
		}
	}()
	return d
}

func result(id int64, app ber.Tag, code int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, app, nil, "result")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "code"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "dn"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "msg"))
	p.AppendChild(r)
	return p
}

func (d *fakeDirectory) serve(c net.Conn) {
	defer c.Close()
	for {
		pkt, err := ber.ReadPacket(c)
		if err != nil || len(pkt.Children) < 2 {
			return
		}
		id, _ := pkt.Children[0].Value.(int64)
		op := pkt.Children[1]
		switch op.Tag {
		case appBindRequest:
			dn, _ := op.Children[1].Value.(string)
			pw := op.Children[2].Data.String()
			code := int64(ldapInvalidCreds)
			if (dn == "cn=svc,dc=x" && pw == "svc-pass") || (strings.HasPrefix(dn, "uid=alice") && pw == "right") {
				code = ldapResultSuccess
			}
			c.Write(result(id, appBindResponse, code).Bytes())
		case appSearchRequest:
			d.mu.Lock()
			d.filters = append(d.filters, ldapFilterString(op.Children[6]))
			entries, groups := d.entries, d.groups
			d.mu.Unlock()
			for _, dn := range entries {
				p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "resp")
				p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
				e := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchEntry, nil, "entry")
				e.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "dn"))
				attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs")
				a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attr")
				a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "memberOf", "name"))
				vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
				for _, g := range groups {
					vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, g, "v"))
				}
				a.AppendChild(vals)
				attrs.AppendChild(a)
				e.AppendChild(attrs)
				p.AppendChild(e)
				c.Write(p.Bytes())
			}
			c.Write(result(id, appSearchDone, ldapResultSuccess).Bytes())
		case appUnbindRequest:
			return
		}
	}
}

// ldapFilterString 取出过滤器中所有断言的值，足够验证用户名是否被转义。
func ldapFilterString(p *ber.Packet) string {
	var b strings.Builder
	var walk func(*ber.Packet)
	walk = func(p *ber.Packet) {
		if len(p.Children) == 0 {
			b.WriteString(p.Data.String())
			b.WriteByte(' ')
		}
		for _, c := range p.Children {
			walk(c)
		}
	}
	walk(p)
	return b.String()
}

func newLDAP(t *testing.T, d *fakeDirectory, m config.RoleMap) *LDAP {
	t.Helper()
	t.Setenv("TEST_LDAP_PW", "svc-pass")
	l, err := NewLDAP(config.LDAPConfig{URL: "ldap://" + d.ln.Addr().String(), AllowPlain: true, BindDN: "cn=svc,dc=x", BindPasswordEnv: "TEST_LDAP_PW",
		BaseDN: "dc=x", UserFilter: "(uid=%s)", RoleMap: m, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLDAPAuthenticate(t *testing.T) {
	d := newDirectory(t)
	l := newLDAP(t, d, config.RoleMap{AnalystGroups: []string{"soc"}})
	role, err := l.Authenticate("alice", "right")
	if err != nil || role != "analyst" {
		t.Fatalf("登录: %q %v", role, err)
	}
	if _, err := l.Authenticate("alice", "wrong"); err == nil {
		t.Fatal("错误密码应失败")
	}
	// 空密码在很多目录服务上是匿名绑定、总是成功
	if _, err := l.Authenticate("alice", ""); err == nil {
		t.Fatal("空密码必须拒绝")
	}
	// 用户名里的过滤器元字符必须转义
	d.mu.Lock()
	d.filters = nil
	d.mu.Unlock()
	l.Authenticate("x)(uid=*", "right")
	d.mu.Lock()
	got := strings.Join(d.filters, "|")
	d.mu.Unlock()
	// 服务端解析出的必须仍是一个等值断言，值就是原样的用户名
	if got != "uid x)(uid=* " {
		t.Fatalf("过滤器注入: %q", got)
	}
}

func TestLDAPRoleAndUniqueness(t *testing.T) {
	d := newDirectory(t)
	if _, err := newLDAP(t, d, config.RoleMap{AdminGroups: []string{"other"}}).Authenticate("alice", "right"); !errors.Is(err, ErrDenied) {
		t.Fatalf("映射不到角色应拒绝: %v", err)
	}
	if role, err := newLDAP(t, d, config.RoleMap{DefaultRole: "viewer"}).Authenticate("alice", "right"); err != nil || role != "viewer" {
		t.Fatalf("默认角色: %q %v", role, err)
	}
	d.mu.Lock()
	d.entries = nil
	d.mu.Unlock()
	if _, err := newLDAP(t, d, config.RoleMap{DefaultRole: "viewer"}).Authenticate("alice", "right"); err == nil {
		t.Fatal("用户不存在应失败")
	}
	d.mu.Lock()
	d.entries = []string{"uid=alice,ou=a,dc=x", "uid=alice,ou=b,dc=x"}
	d.mu.Unlock()
	if _, err := newLDAP(t, d, config.RoleMap{DefaultRole: "viewer"}).Authenticate("alice", "right"); err == nil {
		t.Fatal("用户不唯一应失败")
	}
}
