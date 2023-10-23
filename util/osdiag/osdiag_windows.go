// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osdiag

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/dblohm7/wingoes/com"
	"github.com/dblohm7/wingoes/pe"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
	"tailscale.com/util/osdiag/internal/wsc"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/authenticode"
)

var (
	errUnexpectedResult = errors.New("API call returned an unexpected value")
)

const (
	maxBinaryValueLen  = 128   // we'll truncate any binary values longer than this
	maxRegValueNameLen = 16384 // maximum length supported by Windows + 1
	initialValueBufLen = 80    // large enough to contain a stringified GUID encoded as UTF-16
)

func logSupportInfo(logf logger.Logf, reason LogSupportInfoReason) {
	var b strings.Builder
	if err := getSupportInfo(&b, reason); err != nil {
		logf("error encoding support info: %v", err)
		return
	}
	logf("%s", b.String())
}

const (
	supportInfoKeyModules    = "modules"
	supportInfoKeyPageFile   = "pageFile"
	supportInfoKeyRegistry   = "registry"
	supportInfoKeySecurity   = "securitySoftware"
	supportInfoKeyWinsockLSP = "winsockLSP"
)

func getSupportInfo(w io.Writer, reason LogSupportInfoReason) error {
	output := make(map[string]any)

	regInfo, err := getRegistrySupportInfo(registry.LOCAL_MACHINE, []string{winutil.RegPolicyBase, winutil.RegBase})
	if err == nil {
		output[supportInfoKeyRegistry] = regInfo
	} else {
		output[supportInfoKeyRegistry] = err
	}

	pageFileInfo, err := getPageFileInfo()
	if err == nil {
		output[supportInfoKeyPageFile] = pageFileInfo
	} else {
		output[supportInfoKeyPageFile] = err
	}

	if reason == LogSupportInfoReasonBugReport {
		modInfo, err := getModuleInfo()
		if err == nil {
			output[supportInfoKeyModules] = modInfo
		} else {
			output[supportInfoKeyModules] = err
		}

		output[supportInfoKeySecurity] = getSecurityInfo()

		lspInfo, err := getWinsockLSPInfo()
		if err == nil {
			output[supportInfoKeyWinsockLSP] = lspInfo
		} else {
			output[supportInfoKeyWinsockLSP] = err
		}
	}

	enc := json.NewEncoder(w)
	return enc.Encode(output)
}

type getRegistrySupportInfoBufs struct {
	nameBuf  []uint16
	valueBuf []byte
}

func getRegistrySupportInfo(root registry.Key, subKeys []string) (map[string]any, error) {
	bufs := getRegistrySupportInfoBufs{
		nameBuf:  make([]uint16, maxRegValueNameLen),
		valueBuf: make([]byte, initialValueBufLen),
	}

	output := make(map[string]any)

	for _, subKey := range subKeys {
		if err := getRegSubKey(root, subKey, 5, &bufs, output); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return nil, fmt.Errorf("getRegistrySupportInfo: %w", err)
		}
	}

	return output, nil
}

func keyString(key registry.Key, subKey string) string {
	var keyStr string
	switch key {
	case registry.CLASSES_ROOT:
		keyStr = `HKCR\`
	case registry.CURRENT_USER:
		keyStr = `HKCU\`
	case registry.LOCAL_MACHINE:
		keyStr = `HKLM\`
	case registry.USERS:
		keyStr = `HKU\`
	case registry.CURRENT_CONFIG:
		keyStr = `HKCC\`
	case registry.PERFORMANCE_DATA:
		keyStr = `HKPD\`
	default:
	}

	return keyStr + subKey
}

func getRegSubKey(key registry.Key, subKey string, recursionLimit int, bufs *getRegistrySupportInfoBufs, output map[string]any) error {
	keyStr := keyString(key, subKey)
	k, err := registry.OpenKey(key, subKey, registry.READ)
	if err != nil {
		return fmt.Errorf("opening %q: %w", keyStr, err)
	}
	defer k.Close()

	kv := make(map[string]any)
	index := uint32(0)

loopValues:
	for {
		nbuf := bufs.nameBuf
		nameLen := uint32(len(nbuf))
		valueType := uint32(0)
		vbuf := bufs.valueBuf
		valueLen := uint32(len(vbuf))

		err := regEnumValue(k, index, &nbuf[0], &nameLen, nil, &valueType, &vbuf[0], &valueLen)
		switch err {
		case windows.ERROR_NO_MORE_ITEMS:
			break loopValues
		case windows.ERROR_MORE_DATA:
			bufs.valueBuf = make([]byte, valueLen)
			continue
		case nil:
		default:
			return fmt.Errorf("regEnumValue: %w", err)
		}

		var value any

		switch valueType {
		case registry.SZ, registry.EXPAND_SZ:
			value = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&vbuf[0])))
		case registry.BINARY:
			if valueLen > maxBinaryValueLen {
				valueLen = maxBinaryValueLen
			}
			value = append([]byte{}, vbuf[:valueLen]...)
		case registry.DWORD:
			value = binary.LittleEndian.Uint32(vbuf[:4])
		case registry.MULTI_SZ:
			// Adapted from x/sys/windows/registry/(Key).GetStringsValue
			p := (*[1 << 29]uint16)(unsafe.Pointer(&vbuf[0]))[: valueLen/2 : valueLen/2]
			var strs []string
			if len(p) > 0 {
				if p[len(p)-1] == 0 {
					p = p[:len(p)-1]
				}
				strs = make([]string, 0, 5)
				from := 0
				for i, c := range p {
					if c == 0 {
						strs = append(strs, string(utf16.Decode(p[from:i])))
						from = i + 1
					}
				}
			}
			value = strs
		case registry.QWORD:
			value = binary.LittleEndian.Uint64(vbuf[:8])
		default:
			value = fmt.Sprintf("<unsupported value type %d>", valueType)
		}

		kv[windows.UTF16PtrToString(&nbuf[0])] = value
		index++
	}

	if recursionLimit > 0 {
		if sks, err := k.ReadSubKeyNames(0); err == nil {
			for _, sk := range sks {
				if err := getRegSubKey(k, sk, recursionLimit-1, bufs, kv); err != nil {
					return err
				}
			}
		}
	}

	output[keyStr] = kv
	return nil
}

type moduleInfo struct {
	path         string            `json:"-"` // internal use only
	BaseAddress  uintptr           `json:"baseAddress"`
	Size         uint32            `json:"size"`
	DebugInfo    map[string]string `json:"debugInfo,omitempty"` // map for JSON marshaling purposes
	DebugInfoErr error             `json:"debugInfoErr,omitempty"`
	Signature    map[string]string `json:"signature,omitempty"` // map for JSON marshaling purposes
	SignatureErr error             `json:"signatureErr,omitempty"`
	VersionInfo  map[string]string `json:"versionInfo,omitempty"` // map for JSON marshaling purposes
	VersionErr   error             `json:"versionErr,omitempty"`
}

func (mi *moduleInfo) setVersionInfo() {
	vi, err := pe.NewVersionInfo(mi.path)
	if err != nil {
		if !errors.Is(err, pe.ErrNotPresent) {
			mi.VersionErr = err
		}
		return
	}

	info := map[string]string{
		"": vi.VersionNumber().String(),
	}

	ci, err := vi.Field("CompanyName")
	if err == nil {
		info["companyName"] = ci
	}

	mi.VersionInfo = info
}

var errAssertingType = errors.New("asserting DataDirectory type")

func (mi *moduleInfo) setDebugInfo() {
	pem, err := pe.NewPEFromBaseAddressAndSize(mi.BaseAddress, mi.Size)
	if err != nil {
		mi.DebugInfoErr = err
		return
	}
	defer pem.Close()

	debugDirAny, err := pem.DataDirectoryEntry(pe.IMAGE_DIRECTORY_ENTRY_DEBUG)
	if err != nil {
		if !errors.Is(err, pe.ErrNotPresent) {
			mi.DebugInfoErr = err
		}
		return
	}

	debugDir, ok := debugDirAny.([]pe.IMAGE_DEBUG_DIRECTORY)
	if !ok {
		mi.DebugInfoErr = errAssertingType
		return
	}

	for _, dde := range debugDir {
		if dde.Type != pe.IMAGE_DEBUG_TYPE_CODEVIEW {
			continue
		}

		cv, err := pem.ExtractCodeViewInfo(dde)
		if err == nil {
			mi.DebugInfo = map[string]string{
				"id":  cv.String(),
				"pdb": strings.ToLower(filepath.Base(cv.PDBPath)),
			}
		} else {
			mi.DebugInfoErr = err
		}

		return
	}
}

func (mi *moduleInfo) setAuthenticodeInfo() {
	certSubject, provenance, err := authenticode.QueryCertSubject(mi.path)
	if err != nil {
		if !errors.Is(err, authenticode.ErrSigNotFound) {
			mi.SignatureErr = err
		}
		return
	}

	sigInfo := map[string]string{
		"subject": certSubject,
	}

	switch provenance {
	case authenticode.SigProvEmbedded:
		sigInfo["provenance"] = "embedded"
	case authenticode.SigProvCatalog:
		sigInfo["provenance"] = "catalog"
	default:
	}

	mi.Signature = sigInfo
}

func getModuleInfo() (map[string]moduleInfo, error) {
	// Take a snapshot of all modules currently loaded into the current process
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	result := make(map[string]moduleInfo)
	me := windows.ModuleEntry32{
		Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{})),
	}

	// Now walk the list
	for merr := windows.Module32First(snap, &me); merr == nil; merr = windows.Module32Next(snap, &me) {
		name := strings.ToLower(windows.UTF16ToString(me.Module[:]))
		path := windows.UTF16ToString(me.ExePath[:])
		base := me.ModBaseAddr
		size := me.ModBaseSize

		entry := moduleInfo{
			path:        path,
			BaseAddress: base,
			Size:        size,
		}

		entry.setVersionInfo()
		entry.setDebugInfo()
		entry.setAuthenticodeInfo()

		result[name] = entry
	}

	return result, nil
}

type _WSC_PROVIDER_INFO_TYPE int32

const (
	providerInfoLspCategories _WSC_PROVIDER_INFO_TYPE = 0
)

const (
	_SOCKET_ERROR = -1
)

// Note that wsaProtocolInfo needs to be identical to windows.WSAProtocolInfo;
// the purpose of this type is to have the ability to use it as a reciever in
// the path and categoryFlags funcs defined below.
type wsaProtocolInfo windows.WSAProtocolInfo

func (pi *wsaProtocolInfo) path() (string, error) {
	var errno int32
	var buf [windows.MAX_PATH]uint16
	bufCount := int32(len(buf))
	ret := wscGetProviderPath(&pi.ProviderId, &buf[0], &bufCount, &errno)
	if ret == _SOCKET_ERROR {
		return "", windows.Errno(errno)
	}
	if ret != 0 {
		return "", errUnexpectedResult
	}

	return windows.UTF16ToString(buf[:bufCount]), nil
}

func (pi *wsaProtocolInfo) categoryFlags() (uint32, error) {
	var errno int32
	var result uint32
	bufLen := uintptr(unsafe.Sizeof(result))
	ret := wscGetProviderInfo(&pi.ProviderId, providerInfoLspCategories, unsafe.Pointer(&result), &bufLen, 0, &errno)
	if ret == _SOCKET_ERROR {
		return 0, windows.Errno(errno)
	}
	if ret != 0 {
		return 0, errUnexpectedResult
	}

	return result, nil
}

type wsaProtocolInfoOutput struct {
	Description     string   `json:"description,omitempty"`
	Version         int32    `json:"version"`
	AddressFamily   int32    `json:"addressFamily"`
	SocketType      int32    `json:"socketType"`
	Protocol        int32    `json:"protocol"`
	ServiceFlags1   string   `json:"serviceFlags1"`
	ProviderFlags   string   `json:"providerFlags"`
	Path            string   `json:"path,omitempty"`
	PathErr         error    `json:"pathErr,omitempty"`
	Category        string   `json:"category,omitempty"`
	CategoryErr     error    `json:"categoryErr,omitempty"`
	BaseProviderID  string   `json:"baseProviderID,omitempty"`
	LayerProviderID string   `json:"layerProviderID,omitempty"`
	Chain           []uint32 `json:"chain,omitempty"`
}

func getWinsockLSPInfo() (map[uint32]wsaProtocolInfoOutput, error) {
	protocols, err := enumWinsockProtocols()
	if err != nil {
		return nil, err
	}

	result := make(map[uint32]wsaProtocolInfoOutput, len(protocols))
	for _, p := range protocols {
		v := wsaProtocolInfoOutput{
			Description:   windows.UTF16ToString(p.ProtocolName[:]),
			Version:       p.Version,
			AddressFamily: p.AddressFamily,
			SocketType:    p.SocketType,
			Protocol:      p.Protocol,
			ServiceFlags1: fmt.Sprintf("0x%08X", p.ServiceFlags1), // Serializing as hex string to make the flags easier to decode by human inspection
			ProviderFlags: fmt.Sprintf("0x%08X", p.ProviderFlags),
		}

		switch p.ProtocolChain.ChainLen {
		case windows.BASE_PROTOCOL:
			v.BaseProviderID = p.ProviderId.String()
		case windows.LAYERED_PROTOCOL:
			v.LayerProviderID = p.ProviderId.String()
		default:
			v.Chain = p.ProtocolChain.ChainEntries[:p.ProtocolChain.ChainLen]
		}

		// Queries that are only valid for base and layered protocols (not chains)
		if v.Chain == nil {
			path, err := p.path()
			if err == nil {
				v.Path = strings.ToLower(path)
			} else {
				v.PathErr = err
			}

			category, err := p.categoryFlags()
			if err == nil {
				v.Category = fmt.Sprintf("0x%08X", category)
			} else if !errors.Is(err, windows.WSAEINVALIDPROVIDER) {
				// WSAEINVALIDPROVIDER == "no category info found", so we only log
				// errors other than that one.
				v.CategoryErr = err
			}
		}

		// Chains reference other providers using catalog entry IDs, so we use that
		// value as the key in our map.
		result[p.CatalogEntryId] = v
	}

	return result, nil
}

func enumWinsockProtocols() ([]wsaProtocolInfo, error) {
	// Get the required size
	var errno int32
	var bytesReqd uint32
	ret := wscEnumProtocols(nil, nil, &bytesReqd, &errno)
	if ret != _SOCKET_ERROR {
		return nil, errUnexpectedResult
	}
	if e := windows.Errno(errno); e != windows.WSAENOBUFS {
		return nil, e
	}

	// Allocate
	szEntry := uint32(unsafe.Sizeof(wsaProtocolInfo{}))
	buf := make([]wsaProtocolInfo, bytesReqd/szEntry)

	// Now do the query for real
	bufLen := uint32(len(buf)) * szEntry
	ret = wscEnumProtocols(nil, &buf[0], &bufLen, &errno)
	if ret == _SOCKET_ERROR {
		return nil, windows.Errno(errno)
	}

	return buf, nil
}

type providerKey struct {
	provType wsc.WSC_SECURITY_PROVIDER
	provKey  string
}

var providerKeys = []providerKey{
	providerKey{
		wsc.WSC_SECURITY_PROVIDER_ANTIVIRUS,
		"av",
	},
	providerKey{
		wsc.WSC_SECURITY_PROVIDER_ANTISPYWARE,
		"antispy",
	},
	providerKey{
		wsc.WSC_SECURITY_PROVIDER_FIREWALL,
		"firewall",
	},
}

const (
	maxProvCount = 100
)

type secProductInfo struct {
	Name     string `json:"name,omitempty"`
	NameErr  error  `json:"nameErr,omitempty"`
	State    string `json:"state,omitempty"`
	StateErr error  `json:"stateErr,omitempty"`
}

func getSecurityInfo() map[string]any {
	result := make(map[string]any)

	for _, prov := range providerKeys {
		// Note that we need to obtain a new product list for each provider type;
		// the docs clearly state that we cannot reuse objects.
		productList, err := com.CreateInstance[wsc.WSCProductList](wsc.CLSID_WSCProductList)
		if err != nil {
			result[prov.provKey] = err
			continue
		}

		err = productList.Initialize(prov.provType)
		if err != nil {
			result[prov.provKey] = err
			continue
		}

		n, err := productList.GetCount()
		if err != nil {
			result[prov.provKey] = err
			continue
		}
		if n == 0 {
			continue
		}

		n = min(n, maxProvCount)
		values := make([]any, 0, n)

		for i := int32(0); i < n; i++ {
			product, err := productList.GetItem(uint32(i))
			if err != nil {
				values = append(values, err)
				continue
			}

			var value secProductInfo

			value.Name, err = product.GetProductName()
			if err != nil {
				value.NameErr = err
			}

			state, err := product.GetProductState()
			if err == nil {
				switch state {
				case wsc.WSC_SECURITY_PRODUCT_STATE_ON:
					value.State = "on"
				case wsc.WSC_SECURITY_PRODUCT_STATE_OFF:
					value.State = "off"
				case wsc.WSC_SECURITY_PRODUCT_STATE_SNOOZED:
					value.State = "snoozed"
				case wsc.WSC_SECURITY_PRODUCT_STATE_EXPIRED:
					value.State = "expired"
				default:
					value.State = fmt.Sprintf("<unknown state value %d>", state)
				}
			} else {
				value.StateErr = err
			}

			values = append(values, value)
		}

		result[prov.provKey] = values
	}

	return result
}

type _MEMORYSTATUSEX struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func getPageFileInfo() (map[string]any, error) {
	memStatus := _MEMORYSTATUSEX{
		Length: uint32(unsafe.Sizeof(_MEMORYSTATUSEX{})),
	}
	if err := globalMemoryStatusEx(&memStatus); err != nil {
		return nil, err
	}

	result := map[string]any{
		"bytesAvailable": memStatus.AvailPageFile,
		"bytesTotal":     memStatus.TotalPageFile,
	}

	if entries, err := getEffectivePageFileValue(); err == nil {
		// autoManaged is set to true when there is at least one page file that
		// is automatically managed.
		autoManaged := false

		// If there is only one entry that consists of only one part, then
		// the page files are 100% managed by the system.
		// If there are multiple entries, then each one must be checked.
		// Each entry then consists of three components, deliminated by spaces.
		// If the latter two components are both "0", then that entry is auto-managed.
		for _, entry := range entries {
			if parts := strings.Split(entry, " "); (len(parts) == 1 && len(entries) == 1) ||
				(len(parts) == 3 && parts[1] == "0" && parts[2] == "0") {
				autoManaged = true
				break
			}
		}

		result["autoManaged"] = autoManaged
	}

	return result, nil
}

func getEffectivePageFileValue() ([]string, error) {
	const subKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	// Rare but possible case: the user has updated their page file config but
	// they haven't yet rebooted for the change to take effect. This is the
	// current setting that the machine is still operating with.
	if entries, _, err := key.GetStringsValue("ExistingPageFiles"); err == nil {
		return entries, nil
	}

	// Otherwise we use this value (yes, the above value uses "Page" and this one uses "Paging").
	entries, _, err := key.GetStringsValue("PagingFiles")
	return entries, err
}
