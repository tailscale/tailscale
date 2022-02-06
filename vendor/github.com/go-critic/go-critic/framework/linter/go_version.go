package linter

import (
	"fmt"
	"strconv"
	"strings"
)

type GoVersion struct {
	Major int
	Minor int
}

// GreaterOrEqual performs $v >= $other operation.
//
// In other words, it reports whether $v version constraint can use
// a feature from the $other Go version.
//
// As a special case, Major=0 covers all versions.
func (v GoVersion) GreaterOrEqual(other GoVersion) bool {
	if v.Major == 0 {
		return true
	}
	if v.Major == other.Major {
		return v.Minor >= other.Minor
	}
	return v.Major >= other.Major
}

func parseGoVersion(version string) GoVersion {
	version = strings.TrimPrefix(version, "go")
	if version == "" {
		return GoVersion{}
	}
	parts := strings.Split(version, ".")
	if len(parts) != 2 {
		panic(fmt.Sprintf("invalid Go version format: %s", version))
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		panic(fmt.Sprintf("invalid major version part: %s: %s", parts[0], err))
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(fmt.Sprintf("invalid minor version part: %s: %s", parts[1], err))
	}
	return GoVersion{
		Major: major,
		Minor: minor,
	}
}
