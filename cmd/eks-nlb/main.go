package main

import (
	"github.com/go-logr/zapr"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"tailscale.com/version"
)

// TODO: add an option to configure namespaces to watch
const tsNamespace = "tailscale"

func main() {

	zlog := kzap.NewRaw(kzap.Level(zapcore.DebugLevel)).Sugar()
	logf.SetLogger(zapr.NewLogger(zlog.Desugar()))

	startLog := zlog.Named("startup")

	restConfig := config.GetConfigOrDie()

	nsFilter := cache.ByObject{
		Field: client.InNamespace(tsNamespace).AsSelector(),
	}
	mgrOpts := manager.Options{
		// TODO (irbekrm): stricter filtering what we watch/cache/call
		// reconcilers on. c/r by default starts a watch on any
		// resources that we GET via the controller manager's client.
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}:       nsFilter,
				&corev1.ConfigMap{}: nsFilter,
			},
		},
	}

	mgr, err := manager.New(restConfig, mgrOpts)
	if err != nil {
		startLog.Fatalf("could not create manager: %v", err)
	}

	// TODO: cache metadata only as else this will cache all Pods in cluster
	// -> high memory consumption.
	err = builder.
		ControllerManagedBy(mgr).
		Named("pods-reconciler").
		For(&corev1.Pod{}).
		Complete(&podReconciler{
			logger: zlog.Named("pods-reconciler"),
			Client: mgr.GetClient(),
		})
	if err != nil {
		startLog.Fatalf("could not create pods reconciler: %v", err)
	}

	zlog.Infof("Startup complete, operator running, version: %s", version.Long())
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		startLog.Fatalf("could not start manager: %v", err)
	}
}
