package jen

var reserved = []string{
	/* keywords */
	"break", "default", "func", "interface", "select", "case", "defer", "go", "map", "struct", "chan", "else", "goto", "package", "switch", "const", "fallthrough", "if", "range", "type", "continue", "for", "import", "return", "var",
	/* predeclared */
	"bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "true", "false", "iota", "nil", "append", "cap", "close", "complex", "copy", "delete", "imag", "len", "make", "new", "panic", "print", "println", "real", "recover",
	/* common variables */
	"err",
}

// IsReservedWord returns if this is a reserved word in go
func IsReservedWord(alias string) bool {
	for _, name := range reserved {
		if alias == name {
			return true
		}
	}
	return false
}
