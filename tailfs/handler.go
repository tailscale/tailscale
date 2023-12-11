package tailfs

import (
	"net/http"
	"os"

	"tailscale.com/types/logger"
	"tailscale.com/util/runas"
)

type authenticatingHandler struct {
	username string
	proxy    http.Handler
	logf     logger.Logf
}

func newAuthenticatingHandler(share *Share) Handler {

}

// TODO(oxtoacart): add Close() method and use it when we remove the share
func (h *authenticatingHandler) runLoop() {
	executable, err := os.Executable()
	if err != nil {
		h.logf("can't find executable: %v", err)
		return
	}
	for {
		cmd, err := runas.Run(h.username, executable, "net", "http", "serve-files", "--port=0")
	}
}
