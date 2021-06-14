package main

type conv struct {
	FuncSuffix string
	ExtType    string
}

// typeConvs maps from a SOAP type (e.g "fixed.14.4") to the function name
// suffix inside the soap module (e.g "Fixed14_4") and the Go type.
var typeConvs = map[string]conv{
	"ui1":         {"Ui1", "uint8"},
	"ui2":         {"Ui2", "uint16"},
	"ui4":         {"Ui4", "uint32"},
	"ui8":         {"Ui8", "uint64"},
	"i1":          {"I1", "int8"},
	"i2":          {"I2", "int16"},
	"i4":          {"I4", "int32"},
	"int":         {"Int", "int64"},
	"r4":          {"R4", "float32"},
	"r8":          {"R8", "float64"},
	"number":      {"R8", "float64"}, // Alias for r8.
	"fixed.14.4":  {"Fixed14_4", "float64"},
	"float":       {"R8", "float64"},
	"char":        {"Char", "rune"},
	"string":      {"String", "string"},
	"date":        {"Date", "time.Time"},
	"dateTime":    {"DateTime", "time.Time"},
	"dateTime.tz": {"DateTimeTz", "time.Time"},
	"time":        {"TimeOfDay", "soap.TimeOfDay"},
	"time.tz":     {"TimeOfDayTz", "soap.TimeOfDay"},
	"boolean":     {"Boolean", "bool"},
	"bin.base64":  {"BinBase64", "[]byte"},
	"bin.hex":     {"BinHex", "[]byte"},
	"uri":         {"URI", "*url.URL"},
}
