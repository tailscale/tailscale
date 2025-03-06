package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/types/ptr"
)

func TestGatewayWithRoutes(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "metrics", Generation: 1},
		Spec:       tsapi.ProxyClassSpec{},
		Status: tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: 1,
			}}},
	}
	tsGatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tailscale",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "tailscale.com/ts-gateway",
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc, tsGatewayClass).
		WithStatusSubresource(pc).
		Build()
	ft := &fakeTSClient{}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	// Create a test Gateway reconciler
	reconciler := &GatewayReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			tsnetServer:       fakeTsnetServer,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
	}

	// Test cases
	tests := []struct {
		name    string
		gateway *gatewayv1.Gateway
		routes  []client.Object
		wantErr bool
		setupFn func(t *testing.T)
		checkFn func(t *testing.T)
	}{
		{
			name: "gateway with HTTP route",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "tailscale",
					Listeners: []gatewayv1.Listener{{
						Name:     "http",
						Protocol: gatewayv1.HTTPProtocolType,
						Port:     gatewayv1.PortNumber(80),
					}},
				},
			},
			routes: []client.Object{
				&gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{
								Name: "test-gateway",
							}},
						},
						Rules: []gatewayv1.HTTPRouteRule{{
							BackendRefs: []gatewayv1.HTTPBackendRef{{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "test-service",
										Port: ptr.To(gatewayv1.PortNumber(80)),
									},
								},
							}},
						}},
					},
				},
			},
			wantErr: false,
			setupFn: func(t *testing.T) {
				// Create test service
				svc := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
					Spec: corev1.ServiceSpec{
						ClusterIP: "1.2.3.4",
						Ports: []corev1.ServicePort{{
							Port: 80,
						}},
					},
				}
				assert.NoError(t, fc.Create(context.Background(), svc))
			},
			checkFn: func(t *testing.T) {
				// Verify the Gateway status
				gw := &gatewayv1.Gateway{}
				err := fc.Get(context.Background(), types.NamespacedName{
					Namespace: "default",
					Name:      "test-gateway",
				}, gw)
				assert.NoError(t, err)
				fmt.Println("gw: ", gw)
				assert.NotEmpty(t, gw.Status.Addresses)
			},
		},
	}

	// Run test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			if tc.setupFn != nil {
				tc.setupFn(t)
			}

			// Create the Gateway
			err := fc.Create(context.Background(), tc.gateway)
			assert.NoError(t, err)

			// Create routes
			for _, route := range tc.routes {
				err := fc.Create(context.Background(), route)
				assert.NoError(t, err)
			}

			// Run reconciliation
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: tc.gateway.Namespace,
					Name:      tc.gateway.Name,
				},
			}

			_, err = reconciler.Reconcile(context.Background(), req)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Run checks
			if tc.checkFn != nil {
				tc.checkFn(t)
			}
		})
	}
}
