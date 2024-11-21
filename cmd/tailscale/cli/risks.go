// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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

	"tailscale.com/util/testenv"
)

var (
	riskTypes           []string
	riskLoseSSH         = registerRiskType("lose-ssh")
	riskMacAppConnector = registerRiskType("mac-app-connector")
	riskAll             = registerRiskType("all")
)

const riskMacAppConnectorMessage = `
You are trying to configure an app connector on macOS, which is not officially supported due to system limitations. This may result in performance and reliability issues. 

Do not use a macOS app connector for any mission-critical purposes. For the best experience, Linux is the only recommended platform for app connectors.
`

func registerRiskType(riskType string) string {
	riskTypes = append(riskTypes, riskType)
	return riskType
}

// registerAcceptRiskFlag registers the --accept-risk flag. Accepted risks are accounted for
// in presentRiskToUser.
func registerAcceptRiskFlag(f *flag.FlagSet, acceptedRisks *string) {
	f.StringVar(acceptedRisks, "accept-risk", "", "accept risk and skip confirmation for risk types: "+strings.Join(riskTypes, ","))
}

// isRiskAccepted reports whether riskType is in the comma-separated list of
// risks in acceptedRisks.
func isRiskAccepted(riskType, acceptedRisks string) bool {
	for _, r := range strings.Split(acceptedRisks, ",") {
		if r == riskType || r == riskAll {
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

// presentRiskToUser displays the risk message and waits for the user to cancel.
// It returns errorAborted if the user aborts. In tests it returns errAborted
// immediately unless the risk has been explicitly accepted.
func presentRiskToUser(riskType, riskMessage, acceptedRisks string) error {
	if isRiskAccepted(riskType, acceptedRisks) {
		return nil
	}
	if testenv.InTest() {
		return errAborted
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
