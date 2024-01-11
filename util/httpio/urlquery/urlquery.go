// Package urlquery TODO
package urlquery

// option is an option to alter behavior of Marshal and Unmarshal.
// Currently, there are no defined options.
type option interface{ option() }

func Marshal(val any, opts ...option) (query string, err error)

func Unmarshal(query string, val any, opts ...option) (err error)
