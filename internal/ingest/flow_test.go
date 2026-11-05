package ingest

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/flow"
	"netsa/internal/model"
)

// 流量采集：收到 NetFlow v5 数据包后按配置的采样率还原字节数，合并窗口到期后输出会话事件。
func TestFlowCollector(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	m := NewManager(16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.FlowConfig{NetFlow: addr, Window: 200 * time.Millisecond, Exporters: []config.FlowExporter{{CIDR: "127.0.0.0/8", Name: "核心交换机", Sampling: 1000}}}
	if err := m.StartFlow(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	b := binary.BigEndian.AppendUint16(nil, 5)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 1000)
	b = binary.BigEndian.AppendUint32(b, uint32(time.Now().Unix()))
	b = append(b, make([]byte, 12)...)
	b = append(b, 198, 51, 100, 20, 10, 0, 0, 10, 0, 0, 0, 0, 0, 1, 0, 2)
	b = binary.BigEndian.AppendUint32(b, 3)    // 包数
	b = binary.BigEndian.AppendUint32(b, 1500) // 字节数
	b = binary.BigEndian.AppendUint32(b, 900)
	b = binary.BigEndian.AppendUint32(b, 1000)
	b = append(b, 0, 123, 0xad, 0x9c, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case batch := <-m.Out:
			ev := batch[0]
			if ev.Kind != model.KindFirewall || ev.SrcIP != "198.51.100.20" || ev.DstIP != "10.0.0.10" || ev.SrcPort != 123 || ev.DstPort != 44444 ||
				ev.Proto != "udp" || ev.SentBytes != 1500000 || ev.Packets != 3000 || ev.Sampling != 1000 || ev.Format != "netflow_v5" || ev.Source != "netflow" {
				t.Fatalf("流量事件: %+v", ev)
			}
			for _, st := range m.Stats() {
				if st.Name == "netflow" && (st.Parsed != 1 || st.Detected != "netflow_v5（1 台设备）") {
					t.Fatalf("状态: %+v", st)
				}
			}
			return
		case <-tick.C:
			conn.Write(b)
			b = b[:0:0] // 只发一次
		case <-deadline:
			t.Fatal("没有收到流量事件")
		}
	}
}

// 单向流量记录的应答方向：源端口是服务端口、目的端口是更大的临时端口。
func TestResponseFlow(t *testing.T) {
	for _, c := range []struct {
		proto  uint8
		sp, dp uint16
		want   bool
	}{
		{6, 80, 50000, true}, {6, 50000, 80, false}, {17, 123, 44444, true}, {6, 0, 50000, false}, {6, 3306, 51000, true},
		{6, 2000, 3000, false}, {1, 0, 0, false}, {6, 443, 443, false}, {17, 53, 53, false},
	} {
		if got := responseFlow(flow.Record{Proto: c.proto, SrcPort: c.sp, DstPort: c.dp}); got != c.want {
			t.Errorf("%d %d→%d: %v", c.proto, c.sp, c.dp, got)
		}
	}
}
