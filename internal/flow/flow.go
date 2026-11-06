// Package flow 解码 NetFlow v5 / v9、IPFIX 与 sFlow v5 流量记录（P3-1）。
//
// 流量记录弥补会话日志看不到的两类信息：带宽型 DDoS（攻击流量多被运营商或抗 D 设备挡在边界之外，防火墙会话日志里
// 没有或只有很少的记录）与东西向、出站的字节数。记录中的字节数与包数按采样率还原（设备的选项模板、sFlow 样本自带
// 的采样率，或配置中按设备指定）。解码器只读取需要的字段，畸形的数据包整个丢弃，不会越界。
package flow

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// Record 是一条流量记录（已按采样率还原字节数与包数）。
type Record struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8
	Flags            uint8 // TCP 标志位（累计）
	Bytes, Packets   uint64
	Start            time.Time // 流开始时间（设备记录了时；没有记录时与 End 相同）
	End              time.Time // 流结束（或导出）时间
	Denied           bool      // 防火墙事件（NSEL）为拒绝
	Sampling         uint32
}

var errShort = errors.New("数据包不完整")

// 数据长度上限：一个 UDP 数据包内的记录数、模板字段数。
const (
	maxRecords        = 2048
	maxTemplateFields = 128
	maxTemplates      = 4096
	maxPerExporter    = 256 // 每台设备（地址 + 观察域）最多保存的模板数
	templateTTL       = 2 * time.Hour
)

type tmplKey struct {
	exporter netip.Addr
	domain   uint32
	id       uint16
}

type field struct {
	typ, length uint16
	enterprise  bool
}

type template struct {
	fields  []field
	options bool // 选项模板（携带采样率）
	seen    time.Time
}

// Decoder 解码 NetFlow v5 / v9 与 IPFIX，保存各设备的模板与采样率，可并发调用。
type Decoder struct {
	mu          sync.Mutex
	templates   map[tmplKey]*template
	perExporter map[netip.Addr]int    // 每台设备的模板数
	sampling    map[netip.Addr]uint32 // 设备在选项数据中报告的采样率
	// Default 返回设备的默认采样率（配置中按设备指定），为空或返回 0 时按 1 处理
	Default func(exporter netip.Addr) uint32
}

// NewDecoder 创建解码器。
func NewDecoder() *Decoder {
	return &Decoder{templates: map[tmplKey]*template{}, perExporter: map[netip.Addr]int{}, sampling: map[netip.Addr]uint32{}}
}

// Decode 解码一个 NetFlow / IPFIX 数据包，返回记录与识别出的格式（netflow_v5 / netflow_v9 / ipfix）。
func (d *Decoder) Decode(exporter netip.Addr, b []byte, now time.Time) ([]Record, string, error) {
	if len(b) < 4 {
		return nil, "", errShort
	}
	switch binary.BigEndian.Uint16(b) {
	case 5:
		recs, err := d.decodeV5(exporter, b)
		return recs, "netflow_v5", err
	case 9:
		recs, err := d.decodeV9(exporter, b, now)
		return recs, "netflow_v9", err
	case 10:
		recs, err := d.decodeIPFIX(exporter, b, now)
		return recs, "ipfix", err
	}
	return nil, "", errors.New("不是 NetFlow v5 / v9 或 IPFIX 数据包")
}

func (d *Decoder) rate(exporter netip.Addr, reported uint32) uint32 {
	if reported > 1 {
		return reported
	}
	d.mu.Lock()
	r := d.sampling[exporter]
	d.mu.Unlock()
	if r > 1 {
		return r
	}
	if d.Default != nil {
		if r := d.Default(exporter); r > 1 {
			return r
		}
	}
	return 1
}

func (d *Decoder) decodeV5(exporter netip.Addr, b []byte) ([]Record, error) {
	if len(b) < 24 {
		return nil, errShort
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	uptime := binary.BigEndian.Uint32(b[4:])
	base := time.Unix(int64(binary.BigEndian.Uint32(b[8:])), int64(binary.BigEndian.Uint32(b[12:])))
	si := uint32(binary.BigEndian.Uint16(b[22:]) & 0x3fff)
	rate := d.rate(exporter, si)
	if n > maxRecords || len(b) < 24+n*48 {
		return nil, errShort
	}
	out := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		r := b[24+i*48:]
		last := binary.BigEndian.Uint32(r[28:])
		rec := Record{
			Src: netip.AddrFrom4([4]byte(r[0:4])), Dst: netip.AddrFrom4([4]byte(r[4:8])),
			Packets: uint64(binary.BigEndian.Uint32(r[16:])) * uint64(rate), Bytes: uint64(binary.BigEndian.Uint32(r[20:])) * uint64(rate),
			SrcPort: binary.BigEndian.Uint16(r[32:]), DstPort: binary.BigEndian.Uint16(r[34:]), Flags: r[37], Proto: r[38],
			End: uptimeTime(base, uptime, last), Sampling: rate,
		}
		rec.Start = uptimeTime(base, uptime, binary.BigEndian.Uint32(r[24:]))
		out = append(out, rec)
	}
	return out, nil
}

// uptimeTime 把设备启动以来的毫秒数换算为时间。
func uptimeTime(base time.Time, uptime, at uint32) time.Time {
	if at == 0 || at > uptime {
		return base
	}
	return base.Add(-time.Duration(uptime-at) * time.Millisecond)
}

func (d *Decoder) decodeV9(exporter netip.Addr, b []byte, now time.Time) ([]Record, error) {
	if len(b) < 20 {
		return nil, errShort
	}
	uptime := binary.BigEndian.Uint32(b[4:])
	base := time.Unix(int64(binary.BigEndian.Uint32(b[8:])), 0)
	domain := binary.BigEndian.Uint32(b[16:])
	return d.decodeSets(exporter, domain, b[20:], now, false, func(f map[uint16][]byte) (time.Time, time.Time) {
		end := base
		if v, ok := f[21]; ok {
			end = uptimeTime(base, uptime, uint32(beUint(v)))
		}
		start := end
		if v, ok := f[22]; ok {
			start = uptimeTime(base, uptime, uint32(beUint(v)))
		}
		return start, end
	})
}

func (d *Decoder) decodeIPFIX(exporter netip.Addr, b []byte, now time.Time) ([]Record, error) {
	if len(b) < 16 {
		return nil, errShort
	}
	if l := int(binary.BigEndian.Uint16(b[2:])); l < 16 || l > len(b) {
		return nil, errShort
	} else {
		b = b[:l]
	}
	export := time.Unix(int64(binary.BigEndian.Uint32(b[4:])), 0)
	domain := binary.BigEndian.Uint32(b[12:])
	return d.decodeSets(exporter, domain, b[16:], now, true, func(f map[uint16][]byte) (time.Time, time.Time) {
		end := export
		if v, ok := f[153]; ok { // flowEndMilliseconds
			end = time.UnixMilli(int64(beUint(v)))
		} else if v, ok := f[151]; ok { // flowEndSeconds
			end = time.Unix(int64(beUint(v)), 0)
		}
		start := end
		if v, ok := f[152]; ok { // flowStartMilliseconds
			start = time.UnixMilli(int64(beUint(v)))
		} else if v, ok := f[150]; ok { // flowStartSeconds
			start = time.Unix(int64(beUint(v)), 0)
		}
		return start, end
	})
}

// decodeSets 解码 v9 的 FlowSet 与 IPFIX 的 Set。v9：0 模板、1 选项模板；IPFIX：2 模板、3 选项模板；256 起为数据。
func (d *Decoder) decodeSets(exporter netip.Addr, domain uint32, b []byte, now time.Time, ipfix bool, endOf func(map[uint16][]byte) (time.Time, time.Time)) ([]Record, error) {
	var out []Record
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		if l < 4 || l > len(b) {
			return out, errShort
		}
		body := b[4:l]
		b = b[l:]
		switch {
		case !ipfix && id == 0, ipfix && id == 2:
			d.parseTemplates(exporter, domain, body, false, ipfix, now)
		case !ipfix && id == 1, ipfix && id == 3:
			d.parseTemplates(exporter, domain, body, true, ipfix, now)
		case id >= 256:
			d.mu.Lock()
			t := d.templates[tmplKey{exporter, domain, id}]
			d.mu.Unlock()
			if t == nil {
				continue // 还没有收到模板：设备会定期重发
			}
			recs, err := d.parseData(exporter, t, body, endOf)
			out = append(out, recs...)
			if err != nil || len(out) > maxRecords {
				return out, err
			}
		}
	}
	return out, nil
}

func (d *Decoder) parseTemplates(exporter netip.Addr, domain uint32, b []byte, options, ipfix bool, now time.Time) {
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		count := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if options {
			if len(b) < 2 {
				return
			}
			if ipfix {
				b = b[2:] // IPFIX：字段总数之后是 scope 字段数（scope 字段与普通字段同样解析）
			} else {
				// v9 选项模板：scope 长度、option 长度（字节），每个字段 4 字节
				count = (count + int(binary.BigEndian.Uint16(b))) / 4
				b = b[2:]
			}
		}
		if id < 256 || count <= 0 || count > maxTemplateFields {
			return
		}
		fields := make([]field, 0, count)
		for i := 0; i < count; i++ {
			if len(b) < 4 {
				return
			}
			f := field{typ: binary.BigEndian.Uint16(b), length: binary.BigEndian.Uint16(b[2:])}
			b = b[4:]
			if ipfix && f.typ&0x8000 != 0 { // 企业字段：后跟 4 字节企业编号
				if len(b) < 4 {
					return
				}
				f.typ &= 0x7fff
				f.enterprise = true
				b = b[4:]
			}
			fields = append(fields, f)
		}
		d.mu.Lock()
		d.storeTemplateLocked(tmplKey{exporter, domain, id}, &template{fields: fields, options: options, seen: now}, now)
		d.mu.Unlock()
	}
}

// storeTemplateLocked 保存模板（调用方持锁）。每台设备最多 maxPerExporter 个模板；总数达到上限时先清理过期的，
// 仍然满时淘汰最久没有更新的：伪造来源地址发来的大量垃圾模板不能把正常设备的模板挤掉。
func (d *Decoder) storeTemplateLocked(k tmplKey, t *template, now time.Time) {
	if _, ok := d.templates[k]; !ok {
		if d.perExporter[k.exporter] >= maxPerExporter {
			return
		}
		if len(d.templates) >= maxTemplates {
			var oldest tmplKey
			var oldestAt time.Time
			for x, tt := range d.templates {
				if now.Sub(tt.seen) > templateTTL {
					d.dropLocked(x)
					continue
				}
				if oldestAt.IsZero() || tt.seen.Before(oldestAt) {
					oldest, oldestAt = x, tt.seen
				}
			}
			if len(d.templates) >= maxTemplates {
				d.dropLocked(oldest)
			}
		}
		d.perExporter[k.exporter]++
	}
	d.templates[k] = t
}

func (d *Decoder) dropLocked(k tmplKey) {
	if _, ok := d.templates[k]; !ok {
		return
	}
	delete(d.templates, k)
	if d.perExporter[k.exporter]--; d.perExporter[k.exporter] <= 0 {
		delete(d.perExporter, k.exporter)
	}
}

func (d *Decoder) parseData(exporter netip.Addr, t *template, b []byte, endOf func(map[uint16][]byte) (time.Time, time.Time)) ([]Record, error) {
	size := 0
	for _, f := range t.fields {
		if f.length == 0xffff {
			size = -1 // 变长字段：逐条解析
			break
		}
		size += int(f.length)
	}
	if size == 0 {
		return nil, errShort
	}
	var out []Record
	vals := make(map[uint16][]byte, len(t.fields))
	for len(b) > 0 && (size < 0 || len(b) >= size) {
		clear(vals)
		for _, f := range t.fields {
			l := int(f.length)
			if f.length == 0xffff { // IPFIX 变长：1 字节长度，255 时后跟 2 字节长度
				if len(b) < 1 {
					return out, errShort
				}
				l = int(b[0])
				b = b[1:]
				if l == 255 {
					if len(b) < 2 {
						return out, errShort
					}
					l = int(binary.BigEndian.Uint16(b))
					b = b[2:]
				}
			}
			if len(b) < l {
				return out, errShort
			}
			if !f.enterprise {
				vals[f.typ] = b[:l]
			}
			b = b[l:]
		}
		if t.options {
			for _, k := range []uint16{34, 50, 305} { // samplingInterval / samplerRandomInterval / samplingPacketInterval
				if v, ok := vals[k]; ok {
					if r := uint32(beUint(v)); r > 1 && r < 1<<24 {
						d.mu.Lock()
						if _, ok := d.sampling[exporter]; ok || len(d.sampling) < maxTemplates {
							d.sampling[exporter] = r
						}
						d.mu.Unlock()
					}
				}
			}
			continue
		}
		if rec, ok := d.record(exporter, vals, endOf); ok {
			out = append(out, rec)
			if len(out) > maxRecords {
				return out, nil
			}
		}
		if size < 0 && len(b) < 4 {
			break // 变长记录之后的填充
		}
	}
	return out, nil
}

func (d *Decoder) record(exporter netip.Addr, v map[uint16][]byte, endOf func(map[uint16][]byte) (time.Time, time.Time)) (Record, bool) {
	var r Record
	switch {
	case len(v[8]) == 4 && len(v[12]) == 4:
		r.Src, r.Dst = netip.AddrFrom4([4]byte(v[8])), netip.AddrFrom4([4]byte(v[12]))
	case len(v[27]) == 16 && len(v[28]) == 16:
		r.Src, r.Dst = netip.AddrFrom16([16]byte(v[27])).Unmap(), netip.AddrFrom16([16]byte(v[28])).Unmap()
	default:
		return r, false
	}
	r.SrcPort, r.DstPort = uint16(beUint(v[7])), uint16(beUint(v[11]))
	r.Proto, r.Flags = uint8(beUint(v[4])), uint8(beUint(v[6]))
	bytes, pkts := beUint(v[1]), beUint(v[2])
	if bytes == 0 {
		bytes, pkts = beUint(v[85]), beUint(v[86]) // octetTotalCount / packetTotalCount
	}
	if bytes == 0 {
		bytes, pkts = beUint(v[23]), beUint(v[24]) // OUT_BYTES / OUT_PKTS（出向采集）
	}
	// Cisco ASA NSEL：NF_F_FW_EVENT（233）3 为拒绝，NF_F_FWD_FLOW_DELTA_BYTES（231）为正向字节数
	if e, ok := v[233]; ok && beUint(e) == 3 {
		r.Denied = true
	}
	if bytes == 0 {
		bytes = beUint(v[231])
	}
	rate := uint32(1)
	if s, ok := v[34]; ok {
		rate = uint32(beUint(s))
	}
	r.Sampling = d.rate(exporter, rate)
	r.Bytes, r.Packets = bytes*uint64(r.Sampling), pkts*uint64(r.Sampling)
	r.Start, r.End = endOf(v)
	if r.Start.After(r.End) || r.End.Sub(r.Start) > 24*time.Hour {
		r.Start = r.End // 设备时钟异常
	}
	return r, true
}

// beUint 按大端读取 1~8 字节的无符号整数。
func beUint(b []byte) uint64 {
	var n uint64
	for i := 0; i < len(b) && i < 8; i++ {
		n = n<<8 | uint64(b[i])
	}
	return n
}
