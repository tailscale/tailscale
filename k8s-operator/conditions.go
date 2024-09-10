// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

import (
	"slices"
	"time"

	"go.uber.org/zap"
	xslices "golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstime"
)

// SetConnectorCondition ensures that Connector status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes.
func SetConnectorCondition(cn *tsapi.Connector, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) {
	conds := updateCondition(cn.Status.Conditions, conditionType, status, reason, message, gen, clock, logger)
	cn.Status.Conditions = conds
}

// RemoveConnectorCondition will remove condition of the given type if it exists.
func RemoveConnectorCondition(conn *tsapi.Connector, conditionType tsapi.ConditionType) {
	conn.Status.Conditions = slices.DeleteFunc(conn.Status.Conditions, func(cond metav1.Condition) bool {
		return cond.Type == string(conditionType)
	})
}

// SetProxyClassCondition ensures that ProxyClass status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes.
func SetProxyClassCondition(pc *tsapi.ProxyClass, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) {
	conds := updateCondition(pc.Status.Conditions, conditionType, status, reason, message, gen, clock, logger)
	pc.Status.Conditions = conds
}

// SetDNSConfigCondition ensures that DNSConfig status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes
func SetDNSConfigCondition(dnsCfg *tsapi.DNSConfig, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) {
	conds := updateCondition(dnsCfg.Status.Conditions, conditionType, status, reason, message, gen, clock, logger)
	dnsCfg.Status.Conditions = conds
}

// SetServiceCondition ensures that Service status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes.
func SetServiceCondition(svc *corev1.Service, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, clock tstime.Clock, logger *zap.SugaredLogger) {
	conds := updateCondition(svc.Status.Conditions, conditionType, status, reason, message, 0, clock, logger)
	svc.Status.Conditions = conds
}

// RemoveServiceCondition will remove condition of the given type if it exists.
func RemoveServiceCondition(svc *corev1.Service, conditionType tsapi.ConditionType) {
	svc.Status.Conditions = slices.DeleteFunc(svc.Status.Conditions, func(cond metav1.Condition) bool {
		return cond.Type == string(conditionType)
	})
}

// SetRecorderCondition ensures that Recorder status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes.
func SetRecorderCondition(tsr *tsapi.Recorder, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) {
	conds := updateCondition(tsr.Status.Conditions, conditionType, status, reason, message, gen, clock, logger)
	tsr.Status.Conditions = conds
}

func updateCondition(conds []metav1.Condition, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) []metav1.Condition {
	newCondition := metav1.Condition{
		Type:               string(conditionType),
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: gen,
	}

	nowTime := metav1.NewTime(clock.Now().Truncate(time.Second))
	newCondition.LastTransitionTime = nowTime

	idx := xslices.IndexFunc(conds, func(cond metav1.Condition) bool {
		return cond.Type == string(conditionType)
	})

	if idx == -1 {
		conds = append(conds, newCondition)
		return conds
	}

	cond := conds[idx] // update the existing condition

	// If this update doesn't contain a state transition, don't update last
	// transition time.
	if cond.Status == status {
		newCondition.LastTransitionTime = cond.LastTransitionTime
	} else {
		logger.Infof("Status change for condition %s from %s to %s", conditionType, cond.Status, status)
	}
	conds[idx] = newCondition
	return conds
}

func ProxyClassIsReady(pc *tsapi.ProxyClass) bool {
	idx := xslices.IndexFunc(pc.Status.Conditions, func(cond metav1.Condition) bool {
		return cond.Type == string(tsapi.ProxyClassready)
	})
	if idx == -1 {
		return false
	}
	cond := pc.Status.Conditions[idx]
	return cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == pc.Generation
}

func DNSCfgIsReady(cfg *tsapi.DNSConfig) bool {
	idx := xslices.IndexFunc(cfg.Status.Conditions, func(cond metav1.Condition) bool {
		return cond.Type == string(tsapi.NameserverReady)
	})
	if idx == -1 {
		return false
	}
	cond := cfg.Status.Conditions[idx]
	return cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == cfg.Generation
}
