// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

// LogSvcState obtains the state of the Windows service named rootSvcName and
// all of its dependencies, and then emits that state to logf.
func LogSvcState(logf logger.Logf, rootSvcName string) {
	logEntries := []svcStateLogEntry{}

	walkFn := func(svc *mgr.Service, config mgr.Config) {
		status, err := svc.Query()
		if err != nil {
			logf("Failed retrieving Status for service %q: %v", svc.Name, err)
		}

		logEntries = append(logEntries, makeLogEntry(svc, status, config))
	}

	err := walkServices(rootSvcName, walkFn)
	if err != nil {
		logf("LogSvcState error: %v", err)
		return
	}

	json, err := json.MarshalIndent(logEntries, "", "  ")
	if err != nil {
		logf("Error marshaling service log entries: %v", err)
		return
	}

	var builder strings.Builder
	builder.WriteString("State of service ")
	fmt.Fprintf(&builder, "%q", rootSvcName)
	builder.WriteString(" and its dependencies:")
	builder.WriteString("\n")
	builder.Write(json)
	builder.WriteString("\n")

	logf(builder.String())
}

// walkSvcFunc is type of the callback function invoked by WalkServices.
type walkSvcFunc func(*mgr.Service, mgr.Config)

// walkServices opens the service named rootSvcName and walks its dependency
// graph, invoking callback for each service (including the root itself).
func walkServices(rootSvcName string, callback walkSvcFunc) error {
	scm, err := ConnectToLocalSCMForRead()
	if err != nil {
		return fmt.Errorf("connecting to Service Control Manager: %w", err)
	}
	defer scm.Disconnect()

	rootSvc, err := OpenServiceForRead(scm, rootSvcName)
	if err != nil {
		return fmt.Errorf("opening service %q: %w", rootSvcName, err)
	}

	deps := []*mgr.Service{rootSvc}
	defer func() {
		// Any service still in deps when we return is open and must be closed.
		for _, dep := range deps {
			dep.Close()
		}
	}()

	seen := set.Set[string]{}

	for err == nil && len(deps) > 0 {
		err = func() error {
			curSvc := deps[len(deps)-1]
			defer curSvc.Close()

			deps = deps[:len(deps)-1]

			seen.Add(curSvc.Name)

			curCfg, err := curSvc.Config()
			if err != nil {
				return fmt.Errorf("retrieving Config for service %q: %w", curSvc.Name, err)
			}

			callback(curSvc, curCfg)

			for _, depName := range curCfg.Dependencies {
				if seen.Contains(depName) {
					continue
				}

				depSvc, err := OpenServiceForRead(scm, depName)
				if err != nil {
					return fmt.Errorf("opening service %q: %w", depName, err)
				}

				deps = append(deps, depSvc)
			}

			return nil
		}()
	}

	return err
}

type svcStateLogEntry struct {
	ServiceName   string                 `json:"serviceName"`
	ServiceType   string                 `json:"serviceType"`
	State         string                 `json:"state"`
	StartupType   string                 `json:"startupType"`
	Triggers      *_SERVICE_TRIGGER_INFO `json:"triggers,omitempty"`
	TriggersError error                  `json:"triggersError,omitempty"`
}

type _SERVICE_TRIGGER_SPECIFIC_DATA_ITEM struct {
	dataType uint32
	cbData   uint32
	data     *byte
}

type serviceTriggerSpecificDataItemJSONMarshal struct {
	DataType uint32 `json:"dataType"`
	Data     string `json:"data,omitempty"`
}

func (tsdi *_SERVICE_TRIGGER_SPECIFIC_DATA_ITEM) MarshalJSON() ([]byte, error) {
	m := serviceTriggerSpecificDataItemJSONMarshal{DataType: tsdi.dataType}

	const maxDataLen = 128
	data := unsafe.Slice(tsdi.data, tsdi.cbData)
	if len(data) > maxDataLen {
		// Only output the first maxDataLen bytes.
		m.Data = fmt.Sprintf("%s... (truncated %d bytes)", hex.EncodeToString(data[:maxDataLen]), len(data)-maxDataLen)
	} else {
		m.Data = hex.EncodeToString(data)
	}

	return json.Marshal(m)
}

type _SERVICE_TRIGGER struct {
	triggerType    uint32
	action         uint32
	triggerSubtype *windows.GUID
	cDataItems     uint32
	pDataItems     *_SERVICE_TRIGGER_SPECIFIC_DATA_ITEM
}

type serviceTriggerJSONMarshal struct {
	TriggerType    uint32                                `json:"triggerType"`
	Action         uint32                                `json:"action"`
	TriggerSubtype string                                `json:"triggerSubtype,omitempty"`
	DataItems      []_SERVICE_TRIGGER_SPECIFIC_DATA_ITEM `json:"dataItems"`
}

func (ti *_SERVICE_TRIGGER) MarshalJSON() ([]byte, error) {
	m := serviceTriggerJSONMarshal{
		TriggerType: ti.triggerType,
		Action:      ti.action,
		DataItems:   unsafe.Slice(ti.pDataItems, ti.cDataItems),
	}
	if ti.triggerSubtype != nil {
		m.TriggerSubtype = ti.triggerSubtype.String()
	}
	return json.Marshal(m)
}

type _SERVICE_TRIGGER_INFO struct {
	cTriggers uint32
	pTriggers *_SERVICE_TRIGGER
	_         *byte // pReserved
}

func (sti *_SERVICE_TRIGGER_INFO) MarshalJSON() ([]byte, error) {
	triggers := unsafe.Slice(sti.pTriggers, sti.cTriggers)
	return json.Marshal(triggers)
}

// getSvcTriggerInfo obtains information about any system events that may be
// used to start svc. Only relevant for demand-start (aka manual) services.
func getSvcTriggerInfo(svc *mgr.Service) (*_SERVICE_TRIGGER_INFO, error) {
	var desiredLen uint32
	err := queryServiceConfig2(svc.Handle, windows.SERVICE_CONFIG_TRIGGER_INFO,
		nil, 0, &desiredLen)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}

	buf := make([]byte, desiredLen)
	err = queryServiceConfig2(svc.Handle, windows.SERVICE_CONFIG_TRIGGER_INFO,
		&buf[0], desiredLen, &desiredLen)
	if err != nil {
		return nil, err
	}

	return (*_SERVICE_TRIGGER_INFO)(unsafe.Pointer(&buf[0])), nil
}

// makeLogEntry consolidates relevant service information into a svcStateLogEntry.
// We record the values of various service configuration constants as strings
// so the the log entries are easy to interpret at a glance by humans.
func makeLogEntry(svc *mgr.Service, status svc.Status, cfg mgr.Config) (entry svcStateLogEntry) {
	entry.ServiceName = svc.Name

	switch status.State {
	case windows.SERVICE_STOPPED:
		entry.State = "STOPPED"
	case windows.SERVICE_START_PENDING:
		entry.State = "START_PENDING"
	case windows.SERVICE_STOP_PENDING:
		entry.State = "STOP_PENDING"
	case windows.SERVICE_RUNNING:
		entry.State = "RUNNING"
	case windows.SERVICE_CONTINUE_PENDING:
		entry.State = "CONTINUE_PENDING"
	case windows.SERVICE_PAUSE_PENDING:
		entry.State = "PAUSE_PENDING"
	case windows.SERVICE_PAUSED:
		entry.State = "PAUSED"
	case windows.SERVICE_NO_CHANGE:
		entry.State = "NO_CHANGE"
	default:
		entry.State = fmt.Sprintf("Unknown constant %d", status.State)
	}

	switch cfg.ServiceType {
	case windows.SERVICE_FILE_SYSTEM_DRIVER:
		entry.ServiceType = "FILE_SYSTEM_DRIVER"
	case windows.SERVICE_KERNEL_DRIVER:
		entry.ServiceType = "KERNEL_DRIVER"
	case windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_WIN32_SHARE_PROCESS:
		entry.ServiceType = "WIN32"
	default:
		entry.ServiceType = fmt.Sprintf("Unknown constant %d", cfg.ServiceType)
	}

	switch cfg.StartType {
	case windows.SERVICE_BOOT_START:
		entry.StartupType = "BOOT_START"
	case windows.SERVICE_SYSTEM_START:
		entry.StartupType = "SYSTEM_START"
	case windows.SERVICE_AUTO_START:
		if cfg.DelayedAutoStart {
			entry.StartupType = "DELAYED_AUTO_START"
		} else {
			entry.StartupType = "AUTO_START"
		}
	case windows.SERVICE_DEMAND_START:
		entry.StartupType = "DEMAND_START"
		triggerInfo, err := getSvcTriggerInfo(svc)
		if err == nil {
			entry.Triggers = triggerInfo
		} else {
			entry.TriggersError = err
		}
	case windows.SERVICE_DISABLED:
		entry.StartupType = "DISABLED"
	default:
		entry.StartupType = fmt.Sprintf("Unknown constant %d", cfg.StartType)
	}

	return entry
}

// ConnectToLocalSCMForRead connects to the Windows Service Control Manager with
// read-only access. x/sys/windows/svc/mgr/Connect requests read+write access,
// which requires Administrative access rights.
func ConnectToLocalSCMForRead() (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.GENERIC_READ)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

// OpenServiceForRead opens a service with read-only access.
// x/sys/windows/svc/mgr/(*Mgr).OpenService requests read+write access,
// which requires Administrative access rights.
func OpenServiceForRead(scm *mgr.Mgr, svcName string) (*mgr.Service, error) {
	svcNamePtr, err := windows.UTF16PtrFromString(svcName)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(scm.Handle, svcNamePtr, windows.GENERIC_READ)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: svcName, Handle: h}, nil
}
