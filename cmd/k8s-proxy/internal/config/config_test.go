// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/ptr"
)

func TestWatchConfig(t *testing.T) {
	type phase struct {
		config       string
		cancel       bool
		expectedConf *conf.ConfigV1Alpha1
		expectedErr  string
	}

	// Same set of behaviour tests for each config source.
	for _, env := range []string{"file", "kube"} {
		t.Run(env, func(t *testing.T) {
			t.Parallel()

			for _, tc := range []struct {
				name          string
				initialConfig string
				phases        []phase
			}{
				{
					name: "no_config",
					phases: []phase{{
						expectedErr: "error loading initial config",
					}},
				},
				{
					name:          "valid_config",
					initialConfig: `{"version": "v1alpha1", "authKey": "abc123"}`,
					phases: []phase{{
						expectedConf: &conf.ConfigV1Alpha1{
							AuthKey: ptr.To("abc123"),
						},
					}},
				},
				{
					name:          "can_cancel",
					initialConfig: `{"version": "v1alpha1", "authKey": "abc123"}`,
					phases: []phase{
						{
							expectedConf: &conf.ConfigV1Alpha1{
								AuthKey: ptr.To("abc123"),
							},
						},
						{
							cancel: true,
						},
					},
				},
				{
					name:          "can_reload",
					initialConfig: `{"version": "v1alpha1", "authKey": "abc123"}`,
					phases: []phase{
						{
							expectedConf: &conf.ConfigV1Alpha1{
								AuthKey: ptr.To("abc123"),
							},
						},
						{
							config: `{"version": "v1alpha1", "authKey": "def456"}`,
							expectedConf: &conf.ConfigV1Alpha1{
								AuthKey: ptr.To("def456"),
							},
						},
					},
				},
				{
					name:          "ignores_events_with_no_changes",
					initialConfig: `{"version": "v1alpha1", "authKey": "abc123"}`,
					phases: []phase{
						{
							expectedConf: &conf.ConfigV1Alpha1{
								AuthKey: ptr.To("abc123"),
							},
						},
						{
							config: `{"version": "v1alpha1", "authKey": "abc123"}`,
						},
					},
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					root := t.TempDir()
					cl := fake.NewClientset()

					var cfgPath string
					var writeFile func(*testing.T, string)
					if env == "file" {
						cfgPath = filepath.Join(root, kubetypes.KubeAPIServerConfigFile)
						writeFile = func(t *testing.T, content string) {
							if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
								t.Fatalf("error writing config file %q: %v", cfgPath, err)
							}
						}
					} else {
						cfgPath = "kube:default/config-secret"
						writeFile = func(t *testing.T, content string) {
							s := secretFrom(content)
							mustCreateOrUpdate(t, cl, s)
						}
					}
					configChan := make(chan *conf.Config)
					loader := NewConfigLoader(zap.Must(zap.NewDevelopment()).Sugar(), cl.CoreV1(), configChan)
					loader.cfgIgnored = make(chan struct{})
					errs := make(chan error)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()

					writeFile(t, tc.initialConfig)
					go func() {
						errs <- loader.WatchConfig(ctx, cfgPath)
					}()

					for i, p := range tc.phases {
						if p.config != "" {
							writeFile(t, p.config)
						}
						if p.cancel {
							cancel()
						}

						select {
						case cfg := <-configChan:
							if diff := cmp.Diff(*p.expectedConf, cfg.Parsed); diff != "" {
								t.Errorf("unexpected config (-want +got):\n%s", diff)
							}
						case err := <-errs:
							if p.cancel {
								if err != nil {
									t.Fatalf("unexpected error after cancel: %v", err)
								}
							} else if p.expectedErr == "" {
								t.Fatalf("unexpected error: %v", err)
							} else if !strings.Contains(err.Error(), p.expectedErr) {
								t.Fatalf("expected error to contain %q, got %q", p.expectedErr, err.Error())
							}
						case <-loader.cfgIgnored:
							if p.expectedConf != nil {
								t.Fatalf("expected config to be reloaded, but got ignored signal")
							}
						case <-time.After(5 * time.Second):
							t.Fatalf("timed out waiting for expected event in phase: %d", i)
						}
					}
				})
			}
		})
	}
}

func TestWatchConfigSecret_Rewatches(t *testing.T) {
	cl := fake.NewClientset()
	var watchCount int
	var watcher *watch.RaceFreeFakeWatcher
	expected := []string{
		`{"version": "v1alpha1", "authKey": "abc123"}`,
		`{"version": "v1alpha1", "authKey": "def456"}`,
		`{"version": "v1alpha1", "authKey": "ghi789"}`,
	}
	cl.PrependWatchReactor("secrets", func(action ktesting.Action) (handled bool, ret watch.Interface, err error) {
		watcher = watch.NewRaceFreeFake()
		watcher.Add(secretFrom(expected[watchCount]))
		if action.GetVerb() == "watch" && action.GetResource().Resource == "secrets" {
			watchCount++
		}
		return true, watcher, nil
	})

	configChan := make(chan *conf.Config)
	loader := NewConfigLoader(zap.Must(zap.NewDevelopment()).Sugar(), cl.CoreV1(), configChan)

	mustCreateOrUpdate(t, cl, secretFrom(expected[0]))

	errs := make(chan error)
	go func() {
		errs <- loader.watchConfigSecretChanges(t.Context(), "default", "config-secret")
	}()

	for i := range 2 {
		select {
		case cfg := <-configChan:
			if exp := expected[i]; cfg.Parsed.AuthKey == nil || !strings.Contains(exp, *cfg.Parsed.AuthKey) {
				t.Fatalf("expected config to have authKey %q, got: %v", exp, cfg.Parsed.AuthKey)
			}
			if i == 0 {
				watcher.Stop()
			}
		case err := <-errs:
			t.Fatalf("unexpected error: %v", err)
		case <-loader.cfgIgnored:
			t.Fatalf("expected config to be reloaded, but got ignored signal")
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for expected event")
		}
	}

	if watchCount != 2 {
		t.Fatalf("expected 2 watch API calls, got %d", watchCount)
	}
}

func secretFrom(content string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "config-secret",
		},
		Data: map[string][]byte{
			kubetypes.KubeAPIServerConfigFile: []byte(content),
		},
	}
}

func mustCreateOrUpdate(t *testing.T, cl *fake.Clientset, s *corev1.Secret) {
	t.Helper()
	if _, err := cl.CoreV1().Secrets("default").Create(t.Context(), s, metav1.CreateOptions{}); err != nil {
		if _, updateErr := cl.CoreV1().Secrets("default").Update(t.Context(), s, metav1.UpdateOptions{}); updateErr != nil {
			t.Fatalf("error writing config Secret %q: %v", s.Name, updateErr)
		}
	}
}
