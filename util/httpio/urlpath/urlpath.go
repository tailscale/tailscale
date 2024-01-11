// Package urpath TODO
package urlpath

// option is an option to alter behavior of Marshal and Unmarshal.
// Currently, there are no defined options.
type option interface{ option() }

func Marshal(pattern string, val any, opts ...option) (path string, err error)

func Unmarshal(pattern, path string, val any, opts ...option) (err error)
