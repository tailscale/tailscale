package httpstore

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/storetest"
	"tailscale.com/tstest"
)

type mockedHTTPServer struct {
	bs []byte
}

func (m *mockedHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("content-type", contentType)
		if len(m.bs) == 0 {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(m.bs)
		}
	case http.MethodPost:
		if r.Header.Get("content-type") != contentType {
			http.Error(w, "invalid content type", http.StatusBadRequest)
			return
		}
		bs, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		m.bs = bs
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func TestHTTPStoreString(t *testing.T) {
	store := &httpStore{
		requestURL: "http://user:pass@my-server:1234/my-store",
	}
	want := "httpStore(\"http://my-server:1234/my-store\")"
	if got := store.String(); got != want {
		t.Errorf("HTTPStore.String = %q; want %q", got, want)
	}
}

func TestNewHTTPStore(t *testing.T) {
	tstest.PanicOnLog()

	server := httptest.NewServer(new(mockedHTTPServer))
	defer server.Client()

	s, err := newStore(server.URL, server.Client())
	if err != nil {
		t.Fatalf("creating http store failed: %v", err)
	}
	storetest.TestStoreSemantics(t, s)

	// Build a brand new file store and check that both IDs written
	// above are still there.
	s2, err := newStore(server.URL, server.Client())
	if err != nil {
		t.Fatalf("creating second http store failed: %v", err)
	}
	store2 := s.(*httpStore)

	// This is specific to the test, with the non-mocked API, LoadState() should
	// have been already called and successful as no err is returned from newHttpStore()
	if err := s2.(*httpStore).loadState(); err != nil {
		t.Fatalf("loading state from second http store failed: %v", err)
	}

	expected := map[ipn.StateKey]string{
		"foo": "bar",
		"baz": "quux",
	}
	for id, want := range expected {
		bs, err := store2.ReadState(id)
		if err != nil {
			t.Errorf("reading %q (2nd store): %v", id, err)
		}
		if string(bs) != want {
			t.Errorf("reading %q (2nd store): got %q, want %q", id, string(bs), want)
		}
	}
}
