package tailfs

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tailfs/compositefs"
	"tailscale.com/types/logger"
	"tailscale.com/util/runas"
)

// Share represents a folder that's shared with remote Tailfs nodes.
type Share struct {
	// Name is how this share appears on remote nodes.
	Name string `json:"name"`
	// Path is the path to the directory on this machine that's being shared.
	Path string `json:"path"`
	// As is the UNIX or Windows username of the local account used for this
	// share. File read/write permissions are enforced based on this username.
	As string `json:"who"`
	// Readers is a list of Tailscale principals that are allowed to read this
	// share.
	Readers []string `json:"readers,omitempty"`
	// Writers is a list of Tailscale principals that are allowed to write to
	// this share.
	Writers []string `json:"writers,omitempty"`
}

// Principal represents a person or machine attempting to access a share.
type Principal struct {
	IsSelf bool
	UID    tailcfg.UserID
	Groups []string
}

// ForRemote is the TailFS filesystem exposed to remote nodes. It  provides a
// unified WebDAV interface to local directories that have been shared.
type ForRemote interface {
	// SetShares sets the complete set of shares exposed by this node.
	SetShares(shares map[string]*Share)

	// ServeHTTP is like the equivalent method from http.Handler but also
	// accepts a Principal identifying the user making the request.
	ServeHTTP(principal *Principal, w http.ResponseWriter, r *http.Request)

	// Close() stops serving the WebDAV content
	Close() error
}

func NewFileSystemForRemote(logf logger.Logf) ForRemote {
	fs := &fileSystemForRemote{
		logf:        logf,
		cfs:         compositefs.New(logf),
		userProxies: make(map[string]*userProxy),
	}
	return fs
}

type fileSystemForRemote struct {
	logf          logger.Logf
	cfs           compositefs.CompositeFileSystem
	userProxies   map[string]*userProxy
	userProxiesMx sync.RWMutex
}

func (s *fileSystemForRemote) SetShares(shares map[string]*Share) {
	userProxies := make(map[string]*userProxy)
	for _, share := range shares {
		p, found := userProxies[share.As]
		if !found {
			p = &userProxy{
				logf: s.logf,
			}
			userProxies[share.As] = p
		}
		p.shares = append(p.shares, share)
	}
	for _, p := range userProxies {
		go p.runLoop()
	}
	s.userProxiesMx.Lock()
	oldProxies := s.userProxies
	s.userProxies = userProxies
	s.userProxiesMx.Unlock()
	for _, p := range oldProxies {
		if err := p.Close(); err != nil {
			s.logf("error closing old tailfs user proxy: %v", err)
		}
	}
}

func (s *fileSystemForRemote) ServeHTTP(principal *Principal, w http.ResponseWriter, r *http.Request) {
}

func (s *fileSystemForRemote) Close() error {
	return nil
}

// userProxy runs tailscaled serve-tailfs to serve webdav content for the
// given Shares. All Shares are assumed to have the same Who, and the content
// is served as that Who user.
// content at the given paths as that user
type userProxy struct {
	logf           logger.Logf
	shares         []*Share
	reverseProxy   *httputil.ReverseProxy
	reverseProxyMx sync.RWMutex
}

func (p *userProxy) Close() error {
	// TODO(oxtoacart): actually implement this
	return nil
}

func (p *userProxy) runLoop() {
	executable, err := os.Executable()
	if err != nil {
		p.logf("can't find executable: %v", err)
		return
	}
	p.logf("Using executable %v", executable)
	for {
		err := p.run(executable)
		p.logf("error running, will try again: %v", err)
		// TODO(oxtoacart): maybe be smarter about backing off here
		time.Sleep(1 * time.Second)
	}
}

func (p *userProxy) run(executable string) error {
	args := []string{"serve-tailfs"}
	for _, s := range p.shares {
		args = append(args, s.Name, s.Path)
	}
	cmd := runas.Cmd(p.shares[0].As, executable, args...)
	p.logf("Command: %v", cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	defer stdout.Close()
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	r := bufio.NewReader(stdout)
	addr, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read addr: %w", err)
	}
	u, err := url.Parse(fmt.Sprintf("http://%v", strings.TrimSpace(addr)))
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	// send the rest of stdout to discard to avoid blocking
	go io.Copy(io.Discard, r)
	rp := httputil.NewSingleHostReverseProxy(u)
	p.reverseProxyMx.Lock()
	p.reverseProxy = rp
	p.reverseProxyMx.Unlock()
	return cmd.Wait()
}
