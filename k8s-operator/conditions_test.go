// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

func TestSetConnectorCondition(t *testing.T) {
	cn := tsapi.Connector{}
	clock := tstest.NewClock(tstest.ClockOpts{})
	fakeNow := metav1.NewTime(clock.Now().Truncate(time.Second))
	fakePast := metav1.NewTime(clock.Now().Truncate(time.Second).Add(-5 * time.Minute))
	zl, err := zap.NewDevelopment()
	assert.Nil(t, err)

	// Set up a new condition
	SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "someReason", "someMsg", 1, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.ConnectorReady),
					Status:             metav1.ConditionTrue,
					Reason:             "someReason",
					Message:            "someMsg",
					ObservedGeneration: 1,
					LastTransitionTime: fakeNow,
				},
			},
		},
	})

	// Modify status of an existing condition
	cn.Status = tsapi.ConnectorStatus{
		Conditions: []metav1.Condition{
			{
				Type:               string(tsapi.ConnectorReady),
				Status:             metav1.ConditionFalse,
				Reason:             "someReason",
				Message:            "someMsg",
				ObservedGeneration: 1,
				LastTransitionTime: fakePast,
			},
		},
	}
	SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "anotherReason", "anotherMsg", 2, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.ConnectorReady),
					Status:             metav1.ConditionTrue,
					Reason:             "anotherReason",
					Message:            "anotherMsg",
					ObservedGeneration: 2,
					LastTransitionTime: fakeNow,
				},
			},
		},
	})

	// Don't modify last transition time if status hasn't changed
	cn.Status = tsapi.ConnectorStatus{
		Conditions: []metav1.Condition{
			{
				Type:               string(tsapi.ConnectorReady),
				Status:             metav1.ConditionTrue,
				Reason:             "someReason",
				Message:            "someMsg",
				ObservedGeneration: 1,
				LastTransitionTime: fakePast,
			},
		},
	}
	SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "anotherReason", "anotherMsg", 2, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.ConnectorReady),
					Status:             metav1.ConditionTrue,
					Reason:             "anotherReason",
					Message:            "anotherMsg",
					ObservedGeneration: 2,
					LastTransitionTime: fakePast,
				},
			},
		},
	})
}
