package flow

import (
	"encoding/binary"
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

type buf []byte

func (b buf) u8(v uint8) buf   { return append(b, v) }
func (b buf) u16(v uint16) buf { return binary.BigEndian.AppendUint16(b, v) }
func (b buf) u32(v uint32) buf { return binary.BigEndian.AppendUint32(b, v) }
func (b buf) ip(s string) buf  { a := netip.MustParseAddr(s).As4(); return append(b, a[:]...) }

var exp = netip.MustParseAddr("10.0.0.1")

func v5Packet(sampling uint16) []byte {
	b := buf{}.u16(5).u16(2).u32(100000).u32(1730000000).u32(0).u32(1).u8(0).u8(0).u16(sampling)
	rec := func(b buf, src, dst string, sp, dp uint16, pkts, bytes uint32, proto uint8) buf {
		b = b.ip(src).ip(dst).ip("0.0.0.0").u16(1).u16(2).u32(pkts).u32(bytes).u32(90000).u32(99000).u16(sp).u16(dp).u8(0).u8(0x12).u8(proto).u8(0)
		return b.u16(0).u16(0).u8(24).u8(24).u16(0)
	}
	b = rec(b, "198.51.100.7", "10.0.0.10", 53, 40000, 10, 15000, 17)
	return rec(b, "10.0.0.10", "203.0.113.77", 50000, 443, 5, 900, 6)
}

func TestNetFlowV5(t *testing.T) {
	d := NewDecoder()
	recs, f, err := d.Decode(exp, v5Packet(0x4000|100), time.Now())
	if err != nil || f != "netflow_v5" || len(recs) != 2 {
		t.Fatalf("%v %s %+v", err, f, recs)
	}
	r := recs[0]
	if r.Src.String() != "198.51.100.7" || r.Dst.String() != "10.0.0.10" || r.SrcPort != 53 || r.DstPort != 40000 || r.Proto != 17 ||
		r.Bytes != 1500000 || r.Packets != 1000 || r.Sampling != 100 || r.End.Unix() != 1730000000-1 {
		t.Fatalf("v5 记录（采样率 100）: %+v", r)
	}
	// 截断与随机损坏的数据包：不能越界
	p := v5Packet(0)
	for i := range p {
		d.Decode(exp, p[:i], time.Now())
	}
}

func v9Packet() []byte {
	tmpl := buf{}.u16(256).u16(6).u16(8).u16(4).u16(12).u16(4).u16(7).u16(2).u16(11).u16(2).u16(4).u16(1).u16(1).u16(4)
	tset := buf{}.u16(0).u16(uint16(4 + len(tmpl)))
	tset = append(tset, tmpl...)
	// 选项模板：scope（System，4 字节）+ SAMPLING_INTERVAL（34，4 字节）
	opt := buf{}.u16(257).u16(4).u16(4).u16(1).u16(4).u16(34).u16(4)
	oset := buf{}.u16(1).u16(uint16(4 + len(opt) + 2))
	oset = append(append(oset, opt...), 0, 0)
	odata := buf{}.u16(257).u16(4 + 8).u32(0).u32(512)
	data := buf{}.ip("45.33.1.2").ip("10.0.0.10").u16(40000).u16(80).u8(6).u32(64000)
	data = data.ip("45.33.1.3").ip("10.0.0.10").u16(40001).u16(80).u8(6).u32(128000)
	dset := buf{}.u16(256).u16(uint16(4 + len(data) + 2))
	dset = append(append(dset, data...), 0, 0)
	b := buf{}.u16(9).u16(4).u32(100000).u32(1730000000).u32(1).u32(7)
	b = append(b, tset...)
	b = append(b, oset...)
	b = append(b, odata...)
	return append(b, dset...)
}

func TestNetFlowV9(t *testing.T) {
	d := NewDecoder()
	recs, f, err := d.Decode(exp, v9Packet(), time.Now())
	if err != nil || f != "netflow_v9" || len(recs) != 2 {
		t.Fatalf("%v %s %+v", err, f, recs)
	}
	if r := recs[1]; r.Src.String() != "45.33.1.3" || r.DstPort != 80 || r.Proto != 6 || r.Bytes != 128000*512 || r.Sampling != 512 {
		t.Fatalf("v9 记录（选项模板中的采样率 512）: %+v", r)
	}
	// 另一台设备没有模板：数据集被跳过，不报错
	other := netip.MustParseAddr("10.0.0.2")
	p := v9Packet()
	tl := int(binary.BigEndian.Uint16(p[22:]))
	recs, _, _ = d.Decode(other, append(append([]byte{}, p[:20]...), p[20+tl:]...), time.Now())
	if len(recs) != 0 {
		t.Fatalf("没有模板的数据不解析: %+v", recs)
	}
	// 配置的默认采样率
	d2 := NewDecoder()
	d2.Default = func(netip.Addr) uint32 { return 10 }
	q := v9Packet()
	recs, _, _ = d2.Decode(exp, append(append([]byte{}, q[:20+tl]...), q[len(q)-(4+2*17+2):]...), time.Now())
	if len(recs) != 2 || recs[0].Sampling != 10 || recs[0].Bytes != 640000 {
		t.Fatalf("按配置的采样率还原: %+v", recs)
	}
	rnd := rand.New(rand.NewSource(1))
	for range 2000 {
		x := append([]byte{}, p...)
		x[rnd.Intn(len(x))] = byte(rnd.Intn(256))
		d.Decode(exp, x[:rnd.Intn(len(x)+1)], time.Now())
	}
}

func TestIPFIX(t *testing.T) {
	// 模板：源、目的（IPv4）、目的端口、协议、octetDeltaCount（8 字节）、packetDeltaCount（8 字节）、flowEndMilliseconds、企业字段
	tmpl := buf{}.u16(300).u16(8).u16(8).u16(4).u16(12).u16(4).u16(11).u16(2).u16(4).u16(1).u16(1).u16(8).u16(2).u16(8).u16(153).u16(8)
	tmpl = tmpl.u16(0x8000 | 100).u16(2).u32(9999)
	set := buf{}.u16(2).u16(uint16(4 + len(tmpl)))
	set = append(set, tmpl...)
	end := uint64(1730000123456)
	data := buf{}.ip("198.51.100.9").ip("10.0.0.10").u16(53).u8(17)
	data = binary.BigEndian.AppendUint64(data, 3_000_000_000)
	data = binary.BigEndian.AppendUint64(data, 2_000_000)
	data = binary.BigEndian.AppendUint64(data, end)
	data = data.u16(7)
	dset := buf{}.u16(300).u16(uint16(4 + len(data)))
	dset = append(dset, data...)
	body := append(set, dset...)
	b := buf{}.u16(10).u16(uint16(16 + len(body))).u32(1730000200).u32(1).u32(42)
	b = append(b, body...)
	d := NewDecoder()
	recs, f, err := d.Decode(exp, b, time.Now())
	if err != nil || f != "ipfix" || len(recs) != 1 {
		t.Fatalf("%v %s %+v", err, f, recs)
	}
	if r := recs[0]; r.Bytes != 3_000_000_000 || r.Packets != 2_000_000 || r.DstPort != 53 || r.End.UnixMilli() != int64(end) {
		t.Fatalf("IPFIX 记录: %+v", r)
	}
}

func sflowPacket() []byte {
	// 以太网 + VLAN + IPv4 + UDP（反射放大：源端口 123）
	eth := buf{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}.u16(0x8100).u16(100).u16(0x0800)
	ip := buf{0x45, 0}.u16(468).u16(0).u16(0).u8(64).u8(17).u16(0).ip("198.51.100.20").ip("10.0.0.10")
	udp := buf{}.u16(123).u16(44444).u16(448).u16(0)
	hdr := append(append(append(buf{}, eth...), ip...), udp...)
	for len(hdr)%4 != 0 {
		hdr = append(hdr, 0)
	}
	raw := buf{}.u32(1).u32(482).u32(4).u32(uint32(len(hdr)))
	raw = append(raw, hdr...)
	rec := buf{}.u32(1).u32(uint32(len(raw)))
	rec = append(rec, raw...)
	sample := buf{}.u32(1).u32(5).u32(2048).u32(100000).u32(0).u32(1).u32(2).u32(1)
	sample = append(sample, rec...)
	counter := buf{}.u32(2).u32(4).u32(0) // 计数器样本：忽略
	b := buf{}.u32(5).u32(1).ip("10.0.0.254").u32(0).u32(9).u32(1000).u32(2)
	b = b.u32(1).u32(uint32(len(sample)))
	b = append(b, sample...)
	return append(b, counter...)
}

func TestSFlow(t *testing.T) {
	p := sflowPacket()
	recs, agent, err := DecodeSFlow(p, time.Unix(1730000000, 0))
	if err != nil || agent.String() != "10.0.0.254" || len(recs) != 1 {
		t.Fatalf("%v %v %+v", err, agent, recs)
	}
	if r := recs[0]; r.Src.String() != "198.51.100.20" || r.Dst.String() != "10.0.0.10" || r.SrcPort != 123 || r.DstPort != 44444 ||
		r.Proto != 17 || r.Bytes != 482*2048 || r.Packets != 2048 || r.Sampling != 2048 {
		t.Fatalf("sFlow 样本: %+v", r)
	}
	for i := range p {
		DecodeSFlow(p[:i], time.Now())
	}
	rnd := rand.New(rand.NewSource(2))
	for range 2000 {
		x := append([]byte{}, p...)
		x[rnd.Intn(len(x))] = byte(rnd.Intn(256))
		DecodeSFlow(x, time.Now())
	}
}

func TestAggregator(t *testing.T) {
	var a Aggregator
	now := time.Unix(1730000000, 0)
	src, dst := netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("10.0.0.10")
	for i := range 100 {
		a.Add(Record{Src: src, Dst: dst, SrcPort: uint16(1000 + i%2), DstPort: 80, Proto: 6, Bytes: 100, Packets: 1, End: now}, now)
	}
	a.Add(Record{Src: src, Dst: dst, DstPort: 81, Proto: 6, Bytes: 1, Packets: 1, End: now}, now)
	if a.Due(now.Add(5*time.Second)) || !a.Due(now.Add(10*time.Second)) {
		t.Fatal("窗口到期判断")
	}
	out := a.Flush(now.Add(10 * time.Second))
	if len(out) != 2 || a.Len() != 0 {
		t.Fatalf("按目的端口合并: %+v", out)
	}
	for _, r := range out {
		if r.DstPort == 80 && (r.Bytes != 10000 || r.Packets != 100 || r.SrcPort != 0) {
			t.Fatalf("合并的字节数与包数: %+v", r)
		}
	}
}

// 流量数据包来自网络（UDP 源地址可伪造），解码器对任意输入都不能崩溃。
// 运行：go test ./internal/flow -run XXX -fuzz FuzzDecode -fuzztime 60s
func FuzzDecode(f *testing.F) {
	f.Add(v5Packet(0))
	f.Add(v9Packet())
	f.Add(sflowPacket())
	f.Fuzz(func(t *testing.T, b []byte) {
		d := NewDecoder()
		for range 2 { // 第二次带着上一次解析出的模板
			d.Decode(exp, b, time.Now())
		}
		DecodeSFlow(b, time.Now())
	})
}
