package flow

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// DecodeSFlow 解码 sFlow v5 数据报中的流样本（flow sample / expanded flow sample）：原始报文头（以太网、可带 VLAN）
// 解析出地址、端口与协议，样本代表的字节数与包数为帧长 × 采样率、1 × 采样率。计数器样本忽略。
// 返回数据报中的代理（设备）地址。
func DecodeSFlow(b []byte, now time.Time) ([]Record, netip.Addr, error) {
	var agent netip.Addr
	if len(b) < 28 || binary.BigEndian.Uint32(b) != 5 {
		return nil, agent, errors.New("不是 sFlow v5 数据报")
	}
	off := 8
	switch binary.BigEndian.Uint32(b[4:]) {
	case 1:
		agent = netip.AddrFrom4([4]byte(b[8:12]))
		off = 12
	case 2:
		if len(b) < 40 {
			return nil, agent, errShort
		}
		agent = netip.AddrFrom16([16]byte(b[8:24])).Unmap()
		off = 24
	default:
		return nil, agent, errShort
	}
	if len(b) < off+16 {
		return nil, agent, errShort
	}
	n := int(binary.BigEndian.Uint32(b[off+12:]))
	off += 16
	if n > maxRecords {
		return nil, agent, errShort
	}
	var out []Record
	for i := 0; i < n; i++ {
		if len(b) < off+8 {
			return out, agent, errShort
		}
		format := binary.BigEndian.Uint32(b[off:]) & 0xfff
		enterprise := binary.BigEndian.Uint32(b[off:]) >> 12
		l := int(binary.BigEndian.Uint32(b[off+4:]))
		off += 8
		if l < 0 || len(b) < off+l {
			return out, agent, errShort
		}
		s := b[off : off+l]
		off += l
		if enterprise != 0 || format != 1 && format != 3 {
			continue
		}
		var rate uint32
		var recs []byte
		var nrec int
		if format == 1 {
			if len(s) < 32 {
				continue
			}
			rate, nrec, recs = binary.BigEndian.Uint32(s[8:]), int(binary.BigEndian.Uint32(s[28:])), s[32:]
		} else {
			if len(s) < 44 {
				continue
			}
			rate, nrec, recs = binary.BigEndian.Uint32(s[12:]), int(binary.BigEndian.Uint32(s[40:])), s[44:]
		}
		if rate == 0 {
			rate = 1
		}
		for j := 0; j < nrec && len(recs) >= 8; j++ {
			rf := binary.BigEndian.Uint32(recs)
			rl := int(binary.BigEndian.Uint32(recs[4:]))
			if rl < 0 || len(recs) < 8+rl {
				break
			}
			body := recs[8 : 8+rl]
			recs = recs[8+rl:]
			switch rf {
			case 1: // 原始报文头
				if r, ok := rawHeader(body); ok {
					r.Bytes *= uint64(rate)
					r.Packets, r.Sampling, r.End = uint64(rate), rate, now
					out = append(out, r)
				}
			case 3: // 采样的 IPv4：长度、协议、源、目的、源端口、目的端口、TCP 标志、TOS
				if len(body) >= 32 {
					r := Record{Bytes: uint64(binary.BigEndian.Uint32(body)) * uint64(rate), Proto: uint8(binary.BigEndian.Uint32(body[4:])),
						Src: netip.AddrFrom4([4]byte(body[8:12])), Dst: netip.AddrFrom4([4]byte(body[12:16])),
						SrcPort: uint16(binary.BigEndian.Uint32(body[16:])), DstPort: uint16(binary.BigEndian.Uint32(body[20:])),
						Flags: uint8(binary.BigEndian.Uint32(body[24:])), Packets: uint64(rate), Sampling: rate, End: now}
					out = append(out, r)
				}
			}
		}
		if len(out) > maxRecords {
			break
		}
	}
	return out, agent, nil
}

// rawHeader 解析 sFlow 原始报文头记录（header_protocol 1 为以太网，11 / 12 为 IPv4 / IPv6）。
func rawHeader(b []byte) (Record, bool) {
	var r Record
	if len(b) < 16 {
		return r, false
	}
	proto := binary.BigEndian.Uint32(b)
	frame := binary.BigEndian.Uint32(b[4:])
	hl := int(binary.BigEndian.Uint32(b[12:]))
	if hl < 0 || len(b) < 16+hl {
		return r, false
	}
	h := b[16 : 16+hl]
	r.Bytes = uint64(frame)
	ethType := uint16(0)
	switch proto {
	case 1:
		if len(h) < 14 {
			return r, false
		}
		ethType, h = binary.BigEndian.Uint16(h[12:]), h[14:]
		for ethType == 0x8100 || ethType == 0x88a8 { // VLAN 标签（可叠加）
			if len(h) < 4 {
				return r, false
			}
			ethType, h = binary.BigEndian.Uint16(h[2:]), h[4:]
		}
	case 11:
		ethType = 0x0800
	case 12:
		ethType = 0x86dd
	default:
		return r, false
	}
	var l4 []byte
	switch ethType {
	case 0x0800:
		if len(h) < 20 || h[0]>>4 != 4 {
			return r, false
		}
		ihl := int(h[0]&0x0f) * 4
		if ihl < 20 || len(h) < ihl {
			return r, false
		}
		r.Proto = h[9]
		r.Src, r.Dst = netip.AddrFrom4([4]byte(h[12:16])), netip.AddrFrom4([4]byte(h[16:20]))
		if frag := binary.BigEndian.Uint16(h[6:]) & 0x1fff; frag == 0 {
			l4 = h[ihl:]
		}
	case 0x86dd:
		if len(h) < 40 {
			return r, false
		}
		r.Proto = h[6]
		r.Src, r.Dst = netip.AddrFrom16([16]byte(h[8:24])).Unmap(), netip.AddrFrom16([16]byte(h[24:40])).Unmap()
		l4 = h[40:]
	default:
		return r, false
	}
	if (r.Proto == 6 || r.Proto == 17) && len(l4) >= 4 {
		r.SrcPort, r.DstPort = binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		if r.Proto == 6 && len(l4) >= 14 {
			r.Flags = l4[13]
		}
	}
	return r, true
}
