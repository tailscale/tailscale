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
	"k8s.io/client-go/kubernetes/fake"
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
						cfgPath = "kube:config-secret"
						nsFilePath := filepath.Join(root, namespacePath)
						if err := os.MkdirAll(filepath.Dir(nsFilePath), 0o755); err != nil {
							t.Fatalf("error creating namespace directory: %v", err)
						}
						if err := os.WriteFile(nsFilePath, []byte("default"), 0o644); err != nil {
							t.Fatalf("error writing namespace file: %v", err)
						}
						writeFile = func(t *testing.T, content string) {
							s := &corev1.Secret{
								ObjectMeta: metav1.ObjectMeta{
									Name: "config-secret",
								},
								Data: map[string][]byte{
									kubetypes.KubeAPIServerConfigFile: []byte(content),
								},
							}
							if _, err := cl.CoreV1().Secrets("default").Create(t.Context(), s, metav1.CreateOptions{}); err != nil {
								if _, updateErr := cl.CoreV1().Secrets("default").Update(t.Context(), s, metav1.UpdateOptions{}); updateErr != nil {
									t.Fatalf("error writing config Secret %q: %v", cfgPath, updateErr)
								}
							}
						}
					}
					configChan := make(chan *conf.Config)
					l := NewConfigLoader(zap.Must(zap.NewDevelopment()).Sugar(), cl.CoreV1(), configChan)
					l.root = root
					l.cfgIgnored = make(chan struct{})
					errs := make(chan error)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()

					writeFile(t, tc.initialConfig)
					go func() {
						errs <- l.WatchConfig(ctx, cfgPath)
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
						case <-l.cfgIgnored:
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
