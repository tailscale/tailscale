// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package metrics provides logging and reporting for policy settings and scopes.
package metrics

import (
	"strings"
	"sync"

	xmaps "golang.org/x/exp/maps"

	"tailscale.com/syncs"
	"tailscale.com/types/lazy"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/internal/loggerx"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/testenv"
)

var lazyReportMetrics lazy.SyncValue[bool] // used as a test hook

// ShouldReport reports whether metrics should be reported on the current environment.
func ShouldReport() bool {
	return lazyReportMetrics.Get(func() bool {
		// macOS, iOS and tvOS create their own metrics,
		// and we don't have syspolicy on any other platforms.
		return setting.PlatformList{"android", "windows"}.HasCurrent()
	})
}

// Reset metrics for the specified policy origin.
func Reset(origin *setting.Origin) {
	scopeMetrics(origin).Reset()
}

// ReportConfigured updates metrics and logs that the specified setting is
// configured with the given value in the origin.
func ReportConfigured(origin *setting.Origin, setting *setting.Definition, value any) {
	settingMetricsFor(setting).ReportValue(origin, value)
}

// ReportError updates metrics and logs that the specified setting has an error
// in the origin.
func ReportError(origin *setting.Origin, setting *setting.Definition, err error) {
	settingMetricsFor(setting).ReportError(origin, err)
}

// ReportNotConfigured updates metrics and logs that the specified setting is
// not configured in the origin.
func ReportNotConfigured(origin *setting.Origin, setting *setting.Definition) {
	settingMetricsFor(setting).Reset(origin)
}

// metric is an interface implemented by [clientmetric.Metric] and [funcMetric].
type metric interface {
	Add(v int64)
	Set(v int64)
}

// policyScopeMetrics are metrics that apply to an entire policy scope rather
// than a specific policy setting.
type policyScopeMetrics struct {
	hasAny     metric
	numErrored metric
}

func newScopeMetrics(scope setting.Scope) *policyScopeMetrics {
	prefix := metricScopeName(scope)
	// {os}_syspolicy_{scope_unless_device}_any
	// Example: windows_syspolicy_any or windows_syspolicy_user_any.
	hasAny := newMetric([]string{prefix, "any"}, clientmetric.TypeGauge)
	// {os}_syspolicy_{scope_unless_device}_errors
	// Example: windows_syspolicy_errors or windows_syspolicy_user_errors.
	//
	// TODO(nickkhyl): maybe make the `{os}_syspolicy_errors` metric a gauge rather than a counter?
	// It was a counter prior to https://github.com/tailscale/tailscale/issues/12687, so I kept it as such.
	// But I think a gauge makes more sense: syspolicy errors indicate a mismatch between the expected
	// policy value type or format and the actual value read from the underlying store (like the Windows Registry).
	// We'll encounter the same error every time we re-read the policy setting from the backing store
	// until the policy value is corrected by the user, or until we fix the bug in the code or ADMX.
	// There's probably no reason to count and accumulate them over time.
	//
	// Brief discussion: https://github.com/tailscale/tailscale/pull/13113#discussion_r1723475136
	numErrored := newMetric([]string{prefix, "errors"}, clientmetric.TypeCounter)
	return &policyScopeMetrics{hasAny, numErrored}
}

// ReportHasSettings is called when there's any configured policy setting in the scope.
func (m *policyScopeMetrics) ReportHasSettings() {
	if m != nil {
		m.hasAny.Set(1)
	}
}

// ReportError is called when there's any errored policy setting in the scope.
func (m *policyScopeMetrics) ReportError() {
	if m != nil {
		m.numErrored.Add(1)
	}
}

// Reset is called to reset the policy scope metrics, such as when the policy scope
// is about to be reloaded.
func (m *policyScopeMetrics) Reset() {
	if m != nil {
		m.hasAny.Set(0)
		// numErrored is a counter and cannot be (re-)set.
	}
}

// settingMetrics are metrics for a single policy setting in one or more scopes.
type settingMetrics struct {
	definition *setting.Definition
	isSet      []metric // by scope
	hasErrors  []metric // by scope
}

// ReportValue is called when the policy setting is found to be configured in the specified source.
func (m *settingMetrics) ReportValue(origin *setting.Origin, v any) {
	if m == nil {
		return
	}
	if scope := origin.Scope().Kind(); scope >= 0 && int(scope) < len(m.isSet) {
		m.isSet[scope].Set(1)
		m.hasErrors[scope].Set(0)
	}
	scopeMetrics(origin).ReportHasSettings()
	loggerx.Verbosef("%v(%q) = %v", origin, m.definition.Key(), v)
}

// ReportError is called when there's an error with the policy setting in the specified source.
func (m *settingMetrics) ReportError(origin *setting.Origin, err error) {
	if m == nil {
		return
	}
	if scope := origin.Scope().Kind(); int(scope) < len(m.hasErrors) {
		m.isSet[scope].Set(0)
		m.hasErrors[scope].Set(1)
	}
	scopeMetrics(origin).ReportError()
	loggerx.Errorf("%v(%q): %v", origin, m.definition.Key(), err)
}

// Reset is called to reset the policy setting's metrics, such as when
// the policy setting does not exist or the source containing the policy
// is about to be reloaded.
func (m *settingMetrics) Reset(origin *setting.Origin) {
	if m == nil {
		return
	}
	if scope := origin.Scope().Kind(); scope >= 0 && int(scope) < len(m.isSet) {
		m.isSet[scope].Set(0)
		m.hasErrors[scope].Set(0)
	}
}

// metricFn is a function that adds or sets a metric value.
type metricFn func(name string, typ clientmetric.Type, v int64)

// funcMetric implements [metric] by calling the specified add and set functions.
// Used for testing, and with nil functions on platforms that do not support
// syspolicy, and on platforms that report policy metrics from the GUI.
type funcMetric struct {
	name     string
	typ      clientmetric.Type
	add, set metricFn
}

func (m funcMetric) Add(v int64) {
	if m.add != nil {
		m.add(m.name, m.typ, v)
	}
}

func (m funcMetric) Set(v int64) {
	if m.set != nil {
		m.set(m.name, m.typ, v)
	}
}

var (
	lazyDeviceMetrics  lazy.SyncValue[*policyScopeMetrics]
	lazyProfileMetrics lazy.SyncValue[*policyScopeMetrics]
	lazyUserMetrics    lazy.SyncValue[*policyScopeMetrics]
)

func scopeMetrics(origin *setting.Origin) *policyScopeMetrics {
	switch origin.Scope().Kind() {
	case setting.DeviceSetting:
		return lazyDeviceMetrics.Get(func() *policyScopeMetrics {
			return newScopeMetrics(setting.DeviceSetting)
		})
	case setting.ProfileSetting:
		return lazyProfileMetrics.Get(func() *policyScopeMetrics {
			return newScopeMetrics(setting.ProfileSetting)
		})
	case setting.UserSetting:
		return lazyUserMetrics.Get(func() *policyScopeMetrics {
			return newScopeMetrics(setting.UserSetting)
		})
	default:
		panic("unreachable")
	}
}

var (
	settingMetricsMu  sync.RWMutex
	settingMetricsMap map[setting.Key]*settingMetrics
)

func settingMetricsFor(setting *setting.Definition) *settingMetrics {
	settingMetricsMu.RLock()
	metrics, ok := settingMetricsMap[setting.Key()]
	settingMetricsMu.RUnlock()
	if ok {
		return metrics
	}
	return settingMetricsForSlow(setting)
}

func settingMetricsForSlow(d *setting.Definition) *settingMetrics {
	settingMetricsMu.Lock()
	defer settingMetricsMu.Unlock()
	if metrics, ok := settingMetricsMap[d.Key()]; ok {
		return metrics
	}

	// The loop below initializes metrics for each scope where a policy setting defined in 'd'
	// can be configured. The [setting.Definition.Scope] returns the narrowest scope at which the policy
	// setting may be configured, and more specific scopes always have higher numeric values.
	// In other words, [setting.UserSetting] > [setting.ProfileScope] > [setting.DeviceScope].
	// It's impossible for a policy setting to be configured in a scope with a higher numeric value than
	// the [setting.Definition.Scope] returns. Therefore, a policy setting can be configured in at
	// most d.Scope()+1 different scopes, and having d.Scope()+1 metrics for the corresponding scopes
	// is always sufficient for [settingMetrics]; it won't access elements past the end of the slice
	// or need to reallocate with a longer slice if one of those arrives.
	isSet := make([]metric, d.Scope()+1)
	hasErrors := make([]metric, d.Scope()+1)
	for i := range isSet {
		scope := setting.Scope(i)
		// {os}_syspolicy_{key}_{scope_unless_device}
		// Example: windows_syspolicy_AdminConsole or windows_syspolicy_AdminConsole_user.
		isSet[i] = newSettingMetric(d.Key(), scope, "", clientmetric.TypeGauge)
		// {os}_syspolicy_{key}_{scope_unless_device}_error
		// Example: windows_syspolicy_AdminConsole_error or windows_syspolicy_TestSetting01_user_error.
		hasErrors[i] = newSettingMetric(d.Key(), scope, "error", clientmetric.TypeGauge)
	}
	metrics := &settingMetrics{d, isSet, hasErrors}
	mak.Set(&settingMetricsMap, d.Key(), metrics)
	return metrics
}

// hooks for testing
var addMetricTestHook, setMetricTestHook syncs.AtomicValue[metricFn]

// SetHooksForTest sets the specified addMetric and setMetric functions
// as the metric functions for the duration of tb and all its subtests.
func SetHooksForTest(tb internal.TB, addMetric, setMetric metricFn) {
	oldAddMetric := addMetricTestHook.Swap(addMetric)
	oldSetMetric := setMetricTestHook.Swap(setMetric)
	tb.Cleanup(func() {
		addMetricTestHook.Store(oldAddMetric)
		setMetricTestHook.Store(oldSetMetric)
	})

	settingMetricsMu.Lock()
	oldSettingMetricsMap := xmaps.Clone(settingMetricsMap)
	clear(settingMetricsMap)
	settingMetricsMu.Unlock()
	tb.Cleanup(func() {
		settingMetricsMu.Lock()
		settingMetricsMap = oldSettingMetricsMap
		settingMetricsMu.Unlock()
	})

	// (re-)set the scope metrics to use the test hooks for the duration of tb.
	lazyDeviceMetrics.SetForTest(tb, newScopeMetrics(setting.DeviceSetting), nil)
	lazyProfileMetrics.SetForTest(tb, newScopeMetrics(setting.ProfileSetting), nil)
	lazyUserMetrics.SetForTest(tb, newScopeMetrics(setting.UserSetting), nil)
}

func newSettingMetric(key setting.Key, scope setting.Scope, suffix string, typ clientmetric.Type) metric {
	name := strings.ReplaceAll(string(key), setting.KeyPathSeparator, "_")
	return newMetric([]string{name, metricScopeName(scope), suffix}, typ)
}

func newMetric(nameParts []string, typ clientmetric.Type) metric {
	name := strings.Join(slicesx.Filter([]string{internal.OS(), "syspolicy"}, nameParts, isNonEmpty), "_")
	switch {
	case !ShouldReport():
		return &funcMetric{name: name, typ: typ}
	case testenv.InTest():
		return &funcMetric{name, typ, addMetricTestHook.Load(), setMetricTestHook.Load()}
	case typ == clientmetric.TypeCounter:
		return clientmetric.NewCounter(name)
	case typ == clientmetric.TypeGauge:
		return clientmetric.NewGauge(name)
	default:
		panic("unreachable")
	}
}

func isNonEmpty(s string) bool { return s != "" }

func metricScopeName(scope setting.Scope) string {
	switch scope {
	case setting.DeviceSetting:
		return ""
	case setting.ProfileSetting:
		return "profile"
	case setting.UserSetting:
		return "user"
	default:
		panic("unreachable")
	}
}
