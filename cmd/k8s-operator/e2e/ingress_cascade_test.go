// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

// TestL7HAIngressCascade exercises L7 HA Ingress cert issuance against
// Pebble fronted by a rate-limit proxy that mimics LE's calendar-bucket
// behaviour. Requires -devcontrol.
func TestL7HAIngressCascade(t *testing.T) {
	if !*fDevcontrol {
		t.Skip("requires -devcontrol")
	}
	if tnClient == nil {
		t.Skip("requires tnClient")
	}

	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)
	createAndCleanup(t, kubeClient, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: nginx.Name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app.kubernetes.io/name": nginx.Name},
			Ports:    []corev1.ServicePort{{Name: "http", Port: 80}},
		},
	})

	// ProxyClass shortens the cert loop's normal interval so the
	// renewal subtest can observe a renewal organically.
	pc := cascadeProxyClass()
	createAndCleanup(t, kubeClient, pc)

	// Shared ProxyGroup so cert loops persist across subtests.
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("cascade")},
		Spec: tsapi.ProxyGroupSpec{
			Type:       tsapi.ProxyGroupTypeIngress,
			Replicas:   new(int32(2)),
			ProxyClass: pc.Name,
		},
	}
	createAndCleanup(t, kubeClient, pg)
	if err := waitForProxyGroupReady(t, pg.Name, 5*time.Minute); err != nil {
		t.Fatalf("ProxyGroup never became ready: %v", err)
	}

	fastCfg := rest.CopyConfig(restCfg)
	fastCfg.QPS = 100
	fastCfg.Burst = 200
	fastClient, err := client.New(fastCfg, client.Options{Scheme: tsapi.GlobalScheme})
	if err != nil {
		t.Fatalf("fast client: %v", err)
	}

	rl := newRateLimitClient(t)
	if err := rl.waitReady(5 * time.Minute); err != nil {
		t.Fatalf("rate-limit proxy not ready: %v", err)
	}

	t.Run("concurrent_issuance", func(t *testing.T) {
		rl.reset(t)
		runCascade(t, fastClient, pg.Name, nginx.Name, 20, 6*time.Minute, "concurrent")
	})

	t.Run("cascade_failure", func(t *testing.T) {
		// 20s per-order delay + 15 ingresses = 5m of serial work on main
		// (one mutex). The back of the queue blows past the per-call
		// deadline, the loop calls it a failure, and the backoff piles on.
		// Per-domain locking lets them issue concurrently.
		rl.reset(t)
		rl.setDelay(t, 20*time.Second)
		defer rl.setDelay(t, 0)
		runCascade(t, fastClient, pg.Name, nginx.Name, 15, 6*time.Minute, "cascade")
	})

	t.Run("rate_limit_recovery", func(t *testing.T) {
		// 3 per 90s. With Retry-After honoured the second batch lands on
		// the refill cleanly. With a fixed 1m backoff it overshoots,
		// gets another 429, escalates, and lands a window later.
		rl.set(t, 3, 90*time.Second, true)
		defer rl.reset(t)
		runCascade(t, fastClient, pg.Name, nginx.Name, 6, 8*time.Minute, "ratelimit")
	})

	t.Run("saturation", func(t *testing.T) {
		runSaturation(t, fastClient, pg.Name, nginx.Name, rl)
	})

	t.Run("renewal_cycle", func(t *testing.T) {
		runRenewal(t, fastClient, pg.Name, nginx.Name, rl)
	})
}

// runCascade creates n Ingresses against pgName, waits for all to land
// hostnames in parallel, and reports timings.
func runCascade(t *testing.T, cl client.Client, pgName, backendSvc string, n int, timeout time.Duration, tag string) {
	t.Helper()
	names := make([]string, n)
	for i := range n {
		ing := l7Ingress(ns, backendSvc, map[string]string{
			"tailscale.com/proxy-group": pgName,
		})
		ing.Name = generateName(fmt.Sprintf("%s-%02d", tag, i))
		names[i] = ing.Name
		createAndCleanup(t, kubeClient, ing)
	}

	errs := make(chan error, n)
	start := time.Now()
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			_, err := waitForHostname(ctx, cl, ns, name)
			if err != nil {
				errs <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	wg.Wait()
	close(errs)

	var failed int
	for err := range errs {
		failed++
		t.Error(err)
	}
	t.Logf("%s: %d/%d issued in %v", tag, n-failed, n, time.Since(start).Round(time.Second))
}

// runSaturation requests more ingresses than the bucket allows and asks
// what fraction of the bucket's max rate the operator achieved. Measuring
// rate (not 429 count) catches both common failure modes: too cautious
// (e.g. global mutex serialising) and too aggressive (Retry-After misses).
const (
	saturationCap       = 10               // scaled LE: 50/week ≈ 10/min in test
	saturationRefill    = 60 * time.Second
	saturationIngresses = 30
	leWeeklyCap         = 50               // LE certs/week per registered domain
)

func runSaturation(t *testing.T, cl client.Client, pgName, backendSvc string, rl *rateLimitClient) {
	t.Helper()

	rl.set(t, saturationCap, saturationRefill, true)
	defer rl.reset(t)

	windows := (saturationIngresses + saturationCap - 1) / saturationCap
	optimalWall := time.Duration(windows-1)*saturationRefill + 30*time.Second
	runWall := 3 * optimalWall
	if runWall < 6*time.Minute {
		runWall = 6 * time.Minute
	}

	start := time.Now()
	runCascade(t, cl, pgName, backendSvc, saturationIngresses, runWall, "sat")
	wall := time.Since(start)

	s := rl.state(t)
	rate := float64(s.TotalNew) / wall.Seconds()
	maxRate := float64(saturationCap) / saturationRefill.Seconds()
	eff := rate / maxRate

	t.Logf("saturation: %d/%d issued in %v, %d 429s; rate=%.0f%% of bucket max → ~%.0f/week",
		s.TotalNew, saturationIngresses, wall.Round(time.Second), s.Total429,
		eff*100, float64(leWeeklyCap)*eff)

	if s.TotalNew < saturationIngresses {
		t.Errorf("issued %d, want >=%d", s.TotalNew, saturationIngresses)
	}
	if eff < 0.75 {
		t.Errorf("rate %.0f%% of bucket max (want >=75%%)", eff*100)
	}
}

// runRenewal issues 3 certs, locks the bucket so any new (non-replaces)
// order would 429, and waits long enough for the cert loop to fire a
// renewal organically. With ARI "replaces" wired up, renewals bypass the
// locked budget and NotAfter advances; without it (e.g. when
// TS_DEBUG_ACME_FORCE_RENEWAL strips the field), they 429 and NotAfter
// stays put.
//
// Timing: Pebble issues 180s certs, the proxy pods run with
// TS_DEBUG_CERT_LOOP_INTERVAL=30s, so the loop fires after the cert
// reaches 2/3 lifetime (~120s) and triggers a renewal.
func runRenewal(t *testing.T, cl client.Client, pgName, backendSvc string, rl *rateLimitClient) {
	t.Helper()
	const n = 3

	rl.reset(t)

	names := make([]string, n)
	hosts := make(map[string]string, n)
	for i := range n {
		ing := l7Ingress(ns, backendSvc, map[string]string{
			"tailscale.com/proxy-group": pgName,
		})
		ing.Name = generateName(fmt.Sprintf("renewal-%02d", i))
		names[i] = ing.Name
		createAndCleanup(t, kubeClient, ing)
	}
	for _, name := range names {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
		host, err := waitForHostname(ctx, cl, ns, name)
		cancel()
		if err != nil {
			t.Fatalf("initial issuance of %s: %v", name, err)
		}
		hosts[name] = host
	}
	initial := make(map[string]time.Time, n)
	for _, name := range names {
		na, err := certNotAfter(t, hosts[name])
		if err != nil {
			t.Fatalf("NotAfter %s: %v", name, err)
		}
		initial[name] = na
	}
	baseline := rl.state(t)

	// Lock the bucket at the in-window count: any further non-replaces
	// order 429s. Don't reset — keep the existing orders saturating us.
	rl.set(t, baseline.TotalNew, 30*time.Minute, false)

	// Cert lifetime is 180s and the cert loop fires every 30s; renewal
	// becomes due at 2/3 lifetime (120s). Sleep long enough that the
	// loop has fired at least once past that mark.
	time.Sleep(150 * time.Second)

	final := rl.state(t)
	renewals := final.TotalRenew - baseline.TotalRenew
	new429 := final.Total429 - baseline.Total429

	var renewed int
	for _, name := range names {
		na, err := certNotAfter(t, hosts[name])
		if err != nil {
			t.Errorf("NotAfter %s: %v", name, err)
			continue
		}
		if na.After(initial[name]) {
			renewed++
		} else {
			t.Errorf("%s NotAfter did not advance (%v)", name, na.UTC())
		}
	}
	if renewals == 0 {
		t.Errorf("no orders carried ARI replaces")
	}
	if new429 > 0 {
		t.Errorf("renewals 429ed %d times; should be zero with ARI replaces", new429)
	}
	t.Logf("renewal: %d/%d renewed, %d ARI-replaces, %d 429s",
		renewed, n, renewals, new429)
}

// certNotAfter reads NotAfter from the per-domain TLS Secret (named after
// the operator-assigned hostname in cert-share rw mode).
func certNotAfter(t *testing.T, hostname string) (time.Time, error) {
	t.Helper()
	sec := &corev1.Secret{}
	if err := kubeClient.Get(t.Context(), types.NamespacedName{
		Namespace: "tailscale",
		Name:      hostname,
	}, sec); err != nil {
		return time.Time{}, err
	}
	pemBytes := sec.Data["tls.crt"]
	if len(pemBytes) == 0 {
		return time.Time{}, fmt.Errorf("empty tls.crt in Secret %s", hostname)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block in tls.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func waitForHostname(ctx context.Context, cl client.Client, ns, name string) (string, error) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		var ing networkingv1.Ingress
		if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &ing); err != nil {
			if !apierrors.IsNotFound(err) {
				return "", err
			}
		} else if len(ing.Status.LoadBalancer.Ingress) > 0 && ing.Status.LoadBalancer.Ingress[0].Hostname != "" {
			return ing.Status.LoadBalancer.Ingress[0].Hostname, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-t.C:
		}
	}
}

func waitForProxyGroupReady(t *testing.T, name string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var pg tsapi.ProxyGroup
		if err := kubeClient.Get(t.Context(), types.NamespacedName{Name: name}, &pg); err != nil {
			return err
		}
		for _, c := range pg.Status.Conditions {
			if c.Type == "ProxyGroupAvailable" && c.Status == "True" {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for ProxyGroup %s", name)
		}
		time.Sleep(2 * time.Second)
	}
}

// cascadeProxyClass shortens runCertLoop's normal interval to 30s so the
// renewal subtest can observe an organic renewal in ~2 minutes.
func cascadeProxyClass() *tsapi.ProxyClass {
	return &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("cascade")},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleContainer: &tsapi.Container{
						Env: []tsapi.Env{
							{Name: "TS_DEBUG_CERT_LOOP_INTERVAL", Value: "30s"},
						},
					},
				},
			},
		},
	}
}


