// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package config provides watchers for the various supported ways to load a
// config file for k8s-proxy; currently file or Kubernetes Secret.
package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/ptr"
	"tailscale.com/util/testenv"
)

type configLoader struct {
	logger *zap.SugaredLogger
	client clientcorev1.CoreV1Interface

	cfgChan  chan<- *conf.Config
	previous []byte

	once       sync.Once     // For use in tests. To close cfgIgnored.
	cfgIgnored chan struct{} // For use in tests.
}

func NewConfigLoader(logger *zap.SugaredLogger, client clientcorev1.CoreV1Interface, cfgChan chan<- *conf.Config) *configLoader {
	return &configLoader{
		logger:  logger,
		client:  client,
		cfgChan: cfgChan,
	}
}

func (ld *configLoader) WatchConfig(ctx context.Context, path string) error {
	secretNamespacedName, isKubeSecret := strings.CutPrefix(path, "kube:")
	if isKubeSecret {
		secretNamespace, secretName, ok := strings.Cut(secretNamespacedName, string(types.Separator))
		if !ok {
			return fmt.Errorf("invalid Kubernetes Secret reference %q, expected format <namespace>/<name>", path)
		}
		if err := ld.watchConfigSecretChanges(ctx, secretNamespace, secretName); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("error watching config Secret %q: %w", secretNamespacedName, err)
		}

		return nil
	}

	if err := ld.watchConfigFileChanges(ctx, path); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("error watching config file %q: %w", path, err)
	}

	return nil
}

func (ld *configLoader) reloadConfig(ctx context.Context, raw []byte) error {
	if bytes.Equal(raw, ld.previous) {
		if ld.cfgIgnored != nil && testenv.InTest() {
			ld.once.Do(func() {
				close(ld.cfgIgnored)
			})
		}
		return nil
	}

	cfg, err := conf.Load(raw)
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case ld.cfgChan <- &cfg:
	}

	ld.previous = raw
	return nil
}

func (ld *configLoader) watchConfigFileChanges(ctx context.Context, path string) error {
	var (
		tickChan  <-chan time.Time
		eventChan <-chan fsnotify.Event
		errChan   <-chan error
	)

	if w, err := fsnotify.NewWatcher(); err != nil {
		// Creating a new fsnotify watcher would fail for example if inotify was not able to create a new file descriptor.
		// See https://github.com/tailscale/tailscale/issues/15081
		ld.logger.Infof("Failed to create fsnotify watcher on config file %q; watching for changes on 5s timer: %v", path, err)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		tickChan = ticker.C
	} else {
		dir := filepath.Dir(path)
		file := filepath.Base(path)
		ld.logger.Infof("Watching directory %q for changes to config file %q", dir, file)
		defer w.Close()
		if err := w.Add(dir); err != nil {
			return fmt.Errorf("failed to add fsnotify watch: %w", err)
		}
		eventChan = w.Events
		errChan = w.Errors
	}

	// Read the initial config file, but after the watcher is already set up to
	// avoid an unlucky race condition if the config file is edited in between.
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading config file %q: %w", path, err)
	}
	if err := ld.reloadConfig(ctx, b); err != nil {
		return fmt.Errorf("error loading initial config file %q: %w", path, err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errChan:
			if !ok {
				// Watcher was closed.
				return nil
			}
			return fmt.Errorf("watcher error: %w", err)
		case <-tickChan:
		case ev, ok := <-eventChan:
			if !ok {
				// Watcher was closed.
				return nil
			}
			if ev.Name != path || ev.Op&fsnotify.Write == 0 {
				// Ignore irrelevant events.
				continue
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("error reading config file: %w", err)
		}
		// Writers such as os.WriteFile may truncate the file before writing
		// new contents, so it's possible to read an empty file if we read before
		// the write has completed.
		if len(b) == 0 {
			continue
		}
		if err := ld.reloadConfig(ctx, b); err != nil {
			return fmt.Errorf("error reloading config file %q: %v", path, err)
		}
	}
}

func (ld *configLoader) watchConfigSecretChanges(ctx context.Context, secretNamespace, secretName string) error {
	secrets := ld.client.Secrets(secretNamespace)
	w, err := secrets.Watch(ctx, metav1.ListOptions{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		// Re-watch regularly to avoid relying on long-lived connections.
		// See https://github.com/kubernetes-client/javascript/issues/596#issuecomment-786419380
		TimeoutSeconds: ptr.To(int64(600)),
		FieldSelector:  fmt.Sprintf("metadata.name=%s", secretName),
		Watch:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to watch config Secret %q: %w", secretName, err)
	}
	defer func() {
		// May not be the original watcher by the time we exit.
		if w != nil {
			w.Stop()
		}
	}()

	// Get the initial config Secret now we've got the watcher set up.
	secret, err := secrets.Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get config Secret %q: %w", secretName, err)
	}

	if err := ld.configFromSecret(ctx, secret); err != nil {
		return fmt.Errorf("error loading initial config: %w", err)
	}

	ld.logger.Infof("Watching config Secret %q for changes", secretName)
	for {
		var secret *corev1.Secret
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.ResultChan():
			if !ok {
				w.Stop()
				w, err = secrets.Watch(ctx, metav1.ListOptions{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Secret",
						APIVersion: "v1",
					},
					TimeoutSeconds: ptr.To(int64(600)),
					FieldSelector:  fmt.Sprintf("metadata.name=%s", secretName),
					Watch:          true,
				})
				if err != nil {
					return fmt.Errorf("failed to re-watch config Secret %q: %w", secretName, err)
				}
				continue
			}

			switch ev.Type {
			case watch.Added, watch.Modified:
				// New config available to load.
				var ok bool
				secret, ok = ev.Object.(*corev1.Secret)
				if !ok {
					return fmt.Errorf("unexpected object type %T in watch event for config Secret %q", ev.Object, secretName)
				}
				if secret == nil || secret.Data == nil {
					continue
				}
				if err := ld.configFromSecret(ctx, secret); err != nil {
					return fmt.Errorf("error reloading config Secret %q: %v", secret.Name, err)
				}
			case watch.Error:
				return fmt.Errorf("error watching config Secret %q: %v", secretName, ev.Object)
			default:
				// Ignore, no action required.
				continue
			}
		}
	}
}

func (ld *configLoader) configFromSecret(ctx context.Context, s *corev1.Secret) error {
	b := s.Data[kubetypes.KubeAPIServerConfigFile]
	if len(b) == 0 {
		return fmt.Errorf("config Secret %q does not contain expected config in key %q", s.Name, kubetypes.KubeAPIServerConfigFile)
	}

	if err := ld.reloadConfig(ctx, b); err != nil {
		return err
	}

	return nil
}
