// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	riskTypes     []string
	acceptedRisks string
	riskLoseSSH   = registerRiskType("lose-ssh")
)

func registerRiskType(riskType string) string {
	riskTypes = append(riskTypes, riskType)
	return riskType
}

// registerAcceptRiskFlag registers the --accept-risk flag. Accepted risks are accounted for
// in presentRiskToUser.
func registerAcceptRiskFlag(f *flag.FlagSet) {
	f.StringVar(&acceptedRisks, "accept-risk", "", "accept risk and skip confirmation for risk types: "+strings.Join(riskTypes, ","))
}

// riskAccepted reports whether riskType is in acceptedRisks.
func riskAccepted(riskType string) bool {
	for _, r := range strings.Split(acceptedRisks, ",") {
		if r == riskType {
			return true
		}
	}
	return false
}

var errAborted = errors.New("aborted, no changes made")

// riskAbortTimeSeconds is the number of seconds to wait after displaying the
// risk message before continuing with the operation.
// It is used by the presentRiskToUser function below.
const riskAbortTimeSeconds = 5

// presentRiskToUser displays the risk message and waits for the user to
// cancel. It returns errorAborted if the user aborts.
func presentRiskToUser(riskType, riskMessage string) error {
	if riskAccepted(riskType) {
		return nil
	}
	outln(riskMessage)
	printf("To skip this warning, use --accept-risk=%s\n", riskType)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT)
	var msgLen int
	for left := riskAbortTimeSeconds; left > 0; left-- {
		msg := fmt.Sprintf("\rContinuing in %d seconds...", left)
		msgLen = len(msg)
		printf(msg)
		select {
		case <-interrupt:
			printf("\r%s\r", strings.Repeat("x", msgLen+1))
			return errAborted
		case <-time.After(time.Second):
			continue
		}
	}
	printf("\r%s\r", strings.Repeat(" ", msgLen))
	return errAborted
}
