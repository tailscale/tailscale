// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"fmt"
	"io"
)

func WriteTextReport(w io.Writer, target string, r Result) error {
	if target != "" {
		if _, err := fmt.Fprintf(w, "Connecting to host %s\n", target); err != nil {
			return err
		}
	}
	if !r.Path.IsZero() && r.Path.Normalized().Type != PathUnknown {
		src := r.SourceNode
		if src == "" {
			src = "source"
		}
		dst := r.DestinationNode
		if dst == "" {
			dst = "destination"
		}
		if _, err := fmt.Fprintf(w, "%s connected to %s via %s\n", src, dst, r.Path.String()); err != nil {
			return err
		}
	}
	if r.LoggingDisabled {
		if _, err := fmt.Fprintln(w, "Tailperf result logging disabled for this test."); err != nil {
			return err
		}
	}

	includePath := !r.Path.IsZero()
	if includePath {
		if _, err := fmt.Fprintln(w, "Interval          Transfer     Bitrate        Path"); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintln(w, "Interval          Transfer     Bitrate"); err != nil {
		return err
	}
	for _, iv := range r.Intervals {
		if includePath {
			if _, err := fmt.Fprintf(w, "%5.2f-%-5.2f sec  %10s  %13s  %s\n",
				iv.StartSeconds, iv.EndSeconds, formatBytes(iv.TransferBytes), formatBitrate(iv.BitrateBitsPerSecond), iv.Path.String()); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(w, "%5.2f-%-5.2f sec  %10s  %13s\n",
			iv.StartSeconds, iv.EndSeconds, formatBytes(iv.TransferBytes), formatBitrate(iv.BitrateBitsPerSecond)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "- - - - - - - - - - - - - - - - - - - -"); err != nil {
		return err
	}
	totalSeconds := float64(r.DurationMillis) / 1000
	if totalSeconds <= 0 && !r.Started.IsZero() && !r.Ended.IsZero() {
		totalSeconds = r.Ended.Sub(r.Started).Seconds()
	}
	if includePath {
		_, err := fmt.Fprintf(w, "%5.2f-%-5.2f sec  %10s  %13s  %s\n",
			0.0, totalSeconds, formatBytes(r.TransferBytes), formatBitrate(r.BitrateBitsPerSecond), r.Path.String())
		return err
	}
	_, err := fmt.Fprintf(w, "%5.2f-%-5.2f sec  %10s  %13s\n",
		0.0, totalSeconds, formatBytes(r.TransferBytes), formatBitrate(r.BitrateBitsPerSecond))
	return err
}

func formatBytes(n int64) string {
	v := float64(n)
	for _, unit := range []string{"Bytes", "KBytes", "MBytes", "GBytes", "TBytes"} {
		if v < 1024 || unit == "TBytes" {
			if unit == "Bytes" {
				return fmt.Sprintf("%d %s", n, unit)
			}
			return fmt.Sprintf("%.2f %s", v, unit)
		}
		v /= 1024
	}
	return fmt.Sprintf("%d Bytes", n)
}

func formatBitrate(bitsPerSecond float64) string {
	v := bitsPerSecond
	for _, unit := range []string{"bits/sec", "Kbits/sec", "Mbits/sec", "Gbits/sec", "Tbits/sec"} {
		if v < 1000 || unit == "Tbits/sec" {
			return fmt.Sprintf("%.2f %s", v, unit)
		}
		v /= 1000
	}
	return fmt.Sprintf("%.2f bits/sec", bitsPerSecond)
}
