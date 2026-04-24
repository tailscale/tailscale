// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package drive

import (
	"sort"
	"strings"

	"tailscale.com/types/views"
)

// ParseShareAccessNames returns the list of user short names encoded in a
// share name that uses '+' as a separator. Returns nil if the name is not
// a multi-user share. A valid multi-user share must have all non-empty
// segments and at least 2 segments (so "c++" with empty segments returns nil).
func ParseShareAccessNames(shareName string) []string {
	if !strings.Contains(shareName, "+") {
		return nil
	}
	parts := strings.Split(shareName, "+")
	if len(parts) < 2 {
		return nil
	}
	for _, p := range parts {
		if p == "" {
			return nil
		}
	}
	return parts
}

// NormalizeShareNameOrder sorts '+'-separated segments alphabetically.
// Non-multi-user names are returned unchanged.
func NormalizeShareNameOrder(name string) string {
	parts := ParseShareAccessNames(name)
	if parts == nil {
		return name
	}
	sort.Strings(parts)
	return strings.Join(parts, "+")
}

// IsShareAccessibleByUser checks if the given loginName's short name (the
// part before '@') appears in the share's '+'-separated user list. Returns
// true for non-multi-user shares (no name-based restriction).
func IsShareAccessibleByUser(shareName, loginName string) bool {
	parts := ParseShareAccessNames(shareName)
	if parts == nil {
		return true
	}
	short := LoginShortName(loginName)
	domain := loginDomain(loginName)
	for _, p := range parts {
		segShort, segDomain := parseShareSegment(p)
		if segShort != short {
			continue
		}
		// If the segment has no domain qualifier, match on short name only
		// (backward compat). If it has a domain, the login's domain must
		// start with that label.
		if segDomain == "" {
			return true
		}
		if domain != "" && strings.HasPrefix(domain, segDomain) {
			return true
		}
	}
	return false
}

// FilterPermissionsByIdentity takes ACL-derived permissions and further
// restricts them based on share name access control. For each share:
//   - Contains '+' with valid segments: peer's login short name must be listed
//   - Has IsGroup=true on the Share: peer must be in a matching group
//   - Otherwise: no name-based restriction (ACLs only)
//
// The wildcard "*" permission is preserved but only applies to shares the
// peer can access based on name/group rules.
func FilterPermissionsByIdentity(
	aclPerms Permissions,
	loginName string,
	groups []string,
	shares views.SliceView[*Share, ShareView],
) Permissions {
	// If there are no shares with name-based restrictions, return as-is.
	hasRestricted := false
	type shareInfo struct {
		accessible bool
	}
	shareInfos := make(map[string]shareInfo, shares.Len())
	for i := range shares.Len() {
		s := shares.At(i)
		name := s.Name()
		info := shareInfo{accessible: true}
		if s.IsGroup() {
			hasRestricted = true
			info.accessible = matchesGroup(name, groups)
		} else if parts := ParseShareAccessNames(name); parts != nil {
			hasRestricted = true
			info.accessible = false
			short := LoginShortName(loginName)
			domain := loginDomain(loginName)
			for _, p := range parts {
				segShort, segDomain := parseShareSegment(p)
				if segShort != short {
					continue
				}
				if segDomain == "" {
					info.accessible = true
					break
				}
				if domain != "" && strings.HasPrefix(domain, segDomain) {
					info.accessible = true
					break
				}
			}
		}
		shareInfos[name] = info
	}

	if !hasRestricted {
		return aclPerms
	}

	// Expand the wildcard into per-share permissions so we can selectively
	// deny access. The Permissions.For method returns max(specific, wildcard),
	// so the only way to deny a share under a wildcard is to remove the
	// wildcard and grant each accessible share explicitly.
	wildcardPerm := aclPerms[wildcardShare]

	filtered := make(Permissions)

	// Copy non-wildcard ACL entries for accessible shares.
	for shareName, perm := range aclPerms {
		if shareName == wildcardShare {
			continue
		}
		info, ok := shareInfos[shareName]
		if !ok {
			// Share in ACL but not on this node; keep it.
			filtered[shareName] = perm
			continue
		}
		if info.accessible {
			filtered[shareName] = perm
		}
	}

	// If there was a wildcard, expand it to all accessible shares that
	// don't already have an explicit (higher) permission.
	if wildcardPerm > PermissionNone {
		for name, info := range shareInfos {
			if info.accessible {
				if existing := filtered[name]; wildcardPerm > existing {
					filtered[name] = wildcardPerm
				}
			}
		}
	}

	return filtered
}

// LoginShortName extracts the short name from a login name.
// "joe@example.com" → "joe"
func LoginShortName(loginName string) string {
	if i := strings.Index(loginName, "@"); i >= 0 {
		return loginName[:i]
	}
	return loginName
}

// loginDomain extracts the domain part from a login name.
// "alice@example.com" → "example.com"
// "alice" → ""
func loginDomain(loginName string) string {
	if i := strings.Index(loginName, "@"); i >= 0 {
		return loginName[i+1:]
	}
	return ""
}

// LoginDisplayName returns a display name for a login, suitable for use in
// share names. If the login's domain matches tailnetDomain, only the short
// name is returned (e.g. "alice"). Otherwise, the format "shortname(domain)"
// is used (e.g. "alice(company)") where domain has its TLD stripped.
func LoginDisplayName(loginName, tailnetDomain string) string {
	short := LoginShortName(loginName)
	domain := loginDomain(loginName)
	if domain == "" || domain == tailnetDomain {
		return short
	}
	// Strip TLD from domain for brevity: "company.com" → "company"
	domainLabel := domain
	if i := strings.Index(domainLabel, "."); i >= 0 {
		domainLabel = domainLabel[:i]
	}
	return short + "(" + domainLabel + ")"
}

// parseShareSegment parses a share name segment that may contain a domain
// qualifier. "alice(company)" returns ("alice", "company"). "alice" returns
// ("alice", "").
func parseShareSegment(segment string) (shortName, domain string) {
	if i := strings.Index(segment, "("); i >= 0 {
		if j := strings.Index(segment, ")"); j > i {
			return segment[:i], segment[i+1 : j]
		}
	}
	return segment, ""
}

// matchesGroup checks if the share name matches any of the peer's group
// identifiers. Groups can be in the form "group:eng" or "eng@example.com".
func matchesGroup(shareName string, groups []string) bool {
	for _, g := range groups {
		if GroupShortName(g) == shareName {
			return true
		}
	}
	return false
}

// GroupShortName extracts a short group name from a group identifier.
// "group:eng" → "eng", "eng@example.com" → "eng"
func GroupShortName(group string) string {
	if strings.HasPrefix(group, "group:") {
		return strings.TrimPrefix(group, "group:")
	}
	if i := strings.Index(group, "@"); i >= 0 {
		return group[:i]
	}
	return group
}
