// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"net/netip"
	"testing"
)

func TestWindowsPingOutputIsSuccess(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		out  string
		want bool
	}{
		{
			name: "success",
			ip:   "10.0.0.1",
			want: true,
			out: `Pinging 10.0.0.1 with 32 bytes of data:
Reply from 10.0.0.1: bytes=32 time=7ms TTL=64

Ping statistics for 10.0.0.1:
	Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
	Minimum = 7ms, Maximum = 7ms, Average = 7ms
`,
		},
		{
			name: "success_sub_millisecond",
			ip:   "10.0.0.1",
			want: true,
			out: `Pinging 10.0.0.1 with 32 bytes of data:
Reply from 10.0.0.1: bytes=32 time<1ms TTL=64

Ping statistics for 10.0.0.1:
	Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
	Minimum = 7ms, Maximum = 7ms, Average = 7ms
`,
		},
		{
			name: "success_german",
			ip:   "10.0.0.1",
			want: true,
			out: `Ping wird ausgeführt für 10.0.0.1 mit 32 Bytes Daten:
Antwort von from 10.0.0.1: Bytes=32 Zeit=7ms TTL=64

Ping-Statistik für 10.0.0.1:
	Pakete: Gesendet = 4, Empfangen = 4, Verloren = 0 (0% Verlust),
Ca. Zeitangaben in Millisek.:
	Minimum = 7ms, Maximum = 7ms, Mittelwert = 7ms
`,
		},
		{
			name: "success_chinese",
			ip:   "10.0.0.1",
			want: true,
			out: "正在 Ping 10.0.0.1 具有 32 字节的数据:\r\n" +
				"来自 10.0.0.1 的回复: 字节=32 时间=7ms TTL=64\r\n" +
				"\r\n" +
				"10.0.0.1 的 Ping 统计信息:\r\n" +
				"    数据包: 已发送 = 1，已接收 = 1，丢失 = 0 (0% 丢失)，\r\n" +
				"往返行程的估计时间(以毫秒为单位):\r\n" +
				"    最短 = 7ms，最长 = 7ms，平均 = 7ms\r\n",
		},
		{
			name: "success_chinese_sub_millisecond",
			ip:   "10.0.0.1",
			want: true,
			out: "正在 Ping 10.0.0.1 具有 32 字节的数据:\r\n" +
				"来自 10.0.0.1 的回复: 字节=32 时间<1ms TTL=64\r\n" +
				"\r\n" +
				"10.0.0.1 的 Ping 统计信息:\r\n" +
				"    数据包: 已发送 = 1，已接收 = 1，丢失 = 0 (0% 丢失)，\r\n" +
				"往返行程的估计时间(以毫秒为单位):\r\n" +
				"    最短 = 7ms，最长 = 7ms，平均 = 7ms\r\n",
		},
		{
			name: "success_japanese",
			ip:   "10.0.0.1",
			want: true,
			out: "10.0.0.1 に ping を送信しています 32 バイトのデータ:\r\n" +
				"10.0.0.1 からの応答: バイト数 =32 時間 =7ms TTL=64\r\n" +
				"\r\n" +
				"10.0.0.1 の ping 統計:\r\n" +
				"    パケット数: 送信 = 1、受信 = 1、損失 = 0 (0% の損失)、\r\n" +
				"ラウンド トリップの概算時間 (ミリ秒):\r\n" +
				"    最小 = 7ms、最大 = 7ms、平均 = 7ms\r\n",
		},
		{
			name: "unreachable",
			ip:   "10.0.0.6",
			want: false,
			out: `Pinging 10.0.0.6 with 32 bytes of data:
Reply from 10.0.108.189: Destination host unreachable

Ping statistics for 10.0.0.6:
	Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
`,
		},
		{
			name: "unreachable_chinese",
			ip:   "10.0.0.6",
			want: false,
			out: "正在 Ping 10.0.0.6 具有 32 字节的数据:\r\n" +
				"来自 10.0.108.189 的回复: 无法访问目标主机。\r\n" +
				"\r\n" +
				"10.0.0.6 的 Ping 统计信息:\r\n" +
				"    数据包: 已发送 = 1，已接收 = 1，丢失 = 0 (0% 丢失)，\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := windowsPingOutputIsSuccess(netip.MustParseAddr(tt.ip), []byte(tt.out))
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}
