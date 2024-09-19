package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func runDNSStream(ctx context.Context, args []string) error {
	fmt.Printf(`Privacy warning! To stream DNS queries, this tool will set these Tailscale debug flags, which would normally be disabled by default:

   - TS_DEBUG_DNS_FORWARD_SEND=true
   - TS_DEBUG_DNS_INCLUDE_NAMES=true

TS_DEBUG_DNS_FORWARD_SEND instructs Tailscale to log DNS queries and responses as they are handled by the internal DNS forwarder. 

TS_DEBUG_DNS_INCLUDE_NAMES instructs Tailscale to include queried and resolved DNS hostnames in the logs.

Unless the 'TS_NO_LOGS_NO_SUPPORT' flag was previously set, logs are uploaded to Tailscale for diagnostic and debugging purposes, which can be a concern in privacy-sensitive environments.

If you are concerned about the privacy implications of this, run this tool with the '--no-names' flag, which will avoid logging hostnames.`)
	fmt.Printf("\n\n")
	fmt.Println("Press Enter to start streaming DNS logs, or Ctrl+C to quit this tool.")

	buf := bufio.NewReader(os.Stdin)
	_, err := buf.ReadBytes('\n')
	if err != nil {
		fmt.Println(err)
		return nil
	}

	err = localClient.DebugEnvknob(ctx, "TS_DEBUG_DNS_FORWARD_SEND", "true")
	if err != nil {
		fmt.Printf("failed to set TS_DEBUG_DNS_FORWARD_SEND=true: %v\n", err)
		return nil
	}
	err = localClient.DebugEnvknob(ctx, "TS_DEBUG_DNS_INCLUDE_NAMES", "true")
	if err != nil {
		fmt.Printf("failed to set TS_DEBUG_DNS_INCLUDE_NAMES=true: %v\n", err)
		return nil
	}

	logs, err := localClient.TailDaemonLogs(ctx)
	if err != nil {
		return err
	}

	fmt.Println("Streaming DNS logs. Press Ctrl+C to stop.")

	d := json.NewDecoder(logs)
	for {
		var line struct {
			Text    string `json:"text"`
			Verbose int    `json:"v"`
			Time    string `json:"client_time"`
		}
		err := d.Decode(&line)
		if err != nil {
			return err
		}
		text := strings.TrimSpace(line.Text)
		dnsPrefix := "dns: resolver: forward: "
		if !strings.HasPrefix(text, dnsPrefix) {
			continue
		}
		text = strings.TrimPrefix(text, dnsPrefix)
		fmt.Println(text)
	}
}
