// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Viewer is a tool to automate the creation of "view" wrapper types that
// provide read-only accessor methods to underlying fields.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/types"
	"html/template"
	"log"
	"os"
	"strings"

	"tailscale.com/util/codegen"
)

const viewTemplateStr = `{{define "common"}}
// View returns a readonly view of {{.StructName}}.
func (p *{{.StructName}}) View() {{.ViewName}} {
	return {{.ViewName}}{ж: p}
}

// {{.ViewName}} provides a read-only view over {{.StructName}}.
//
// Its methods should only be called if ` + "`Valid()`" + ` returns true.
type {{.ViewName}} struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *{{.StructName}}
}

// Valid reports whether underlying value is non-nil.
func (v {{.ViewName}}) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v {{.ViewName}}) AsStruct() *{{.StructName}}{ 
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v {{.ViewName}}) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *{{.ViewName}}) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x {{.StructName}}
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж=&x
	return nil
}

{{end}}
{{define "valueField"}}func (v {{.ViewName}}) {{.FieldName}}() {{.FieldType}} { return v.ж.{{.FieldName}} }
{{end}}
{{define "byteSliceField"}}func (v {{.ViewName}}) {{.FieldName}}() mem.RO { return mem.B(v.ж.{{.FieldName}}) }
{{end}}
{{define "ipPrefixSliceField"}}func (v {{.ViewName}}) {{.FieldName}}() views.IPPrefixSlice { return views.IPPrefixSliceOf(v.ж.{{.FieldName}}) }
{{end}}
{{define "sliceField"}}func (v {{.ViewName}}) {{.FieldName}}() views.Slice[{{.FieldType}}] { return views.SliceOf(v.ж.{{.FieldName}}) }
{{end}}
{{define "viewSliceField"}}func (v {{.ViewName}}) {{.FieldName}}() views.SliceView[{{.FieldType}},{{.FieldViewName}}] { return views.SliceOfViews[{{.FieldType}},{{.FieldViewName}}](v.ж.{{.FieldName}}) }
{{end}}
{{define "viewField"}}func (v {{.ViewName}}) {{.FieldName}}() {{.FieldType}}View { return v.ж.{{.FieldName}}.View() }
{{end}}
{{define "valuePointerField"}}func (v {{.ViewName}}) {{.FieldName}}() {{.FieldType}} {
	if v.ж.{{.FieldName}} == nil {
		return nil
	}
	x := *v.ж.{{.FieldName}}
	return &x
}

{{end}}
{{define "mapField"}}
func(v {{.ViewName}}) {{.FieldName}}() views.Map[{{.MapKeyType}},{{.MapValueType}}] { return views.MapOf(v.ж.{{.FieldName}})}
{{end}}
{{define "mapFnField"}}
func(v {{.ViewName}}) {{.FieldName}}() views.MapFn[{{.MapKeyType}},{{.MapValueType}},{{.MapValueView}}] { return views.MapFnOf(v.ж.{{.FieldName}}, func (t {{.MapValueType}}) {{.MapValueView}} {
	return {{.MapFn}}
})}
{{end}}
{{define "unsupportedField"}}func(v {{.ViewName}}) {{.FieldName}}() {{.FieldType}} {panic("unsupported")}
{{end}}
{{define "stringFunc"}}func(v {{.ViewName}}) String() string { return v.ж.String() }
{{end}}
{{define "equalFunc"}}func(v {{.ViewName}}) Equal(v2 {{.ViewName}}) bool { return v.ж.Equal(v2.ж) }
{{end}}
`

var viewTemplate *template.Template

func init() {
	viewTemplate = template.Must(template.New("view").Parse(viewTemplateStr))
}

func requiresCloning(t types.Type) (shallow, deep bool, base types.Type) {
	switch v := t.(type) {
	case *types.Pointer:
		_, deep, base = requiresCloning(v.Elem())
		return true, deep, base
	case *types.Slice:
		_, deep, base = requiresCloning(v.Elem())
		return true, deep, base
	}
	p := codegen.ContainsPointers(t)
	return p, p, t
}

func genView(buf *bytes.Buffer, it *codegen.ImportTracker, typ *types.Named, thisPkg *types.Package) {
	t, ok := typ.Underlying().(*types.Struct)
	if !ok || codegen.IsViewType(t) {
		return
	}
	it.Import("encoding/json")
	it.Import("errors")

	args := struct {
		StructName    string
		ViewName      string
		FieldName     string
		FieldType     string
		FieldViewName string

		MapKeyType   string
		MapValueType string
		MapValueView string
		MapFn        string
	}{
		StructName: typ.Obj().Name(),
		ViewName:   typ.Obj().Name() + "View",
	}

	writeTemplate := func(name string) {
		if err := viewTemplate.ExecuteTemplate(buf, name, args); err != nil {
			log.Fatal(err)
		}
	}
	writeTemplate("common")
	for i := 0; i < t.NumFields(); i++ {
		f := t.Field(i)
		fname := f.Name()
		if !f.Exported() {
			continue
		}
		args.FieldName = fname
		fieldType := f.Type()
		if codegen.IsInvalid(fieldType) {
			continue
		}
		if !codegen.ContainsPointers(fieldType) || codegen.IsViewType(fieldType) || codegen.HasNoClone(t.Tag(i)) {
			args.FieldType = it.QualifiedName(fieldType)
			writeTemplate("valueField")
			continue
		}
		switch underlying := fieldType.Underlying().(type) {
		case *types.Slice:
			slice := underlying
			elem := slice.Elem()
			args.FieldType = it.QualifiedName(elem)
			switch elem.String() {
			case "byte":
				it.Import("go4.org/mem")
				writeTemplate("byteSliceField")
			case "inet.af/netip.Prefix", "net/netip.Prefix":
				it.Import("tailscale.com/types/views")
				writeTemplate("ipPrefixSliceField")
			default:
				it.Import("tailscale.com/types/views")
				shallow, deep, base := requiresCloning(elem)
				if deep {
					if _, isPtr := elem.(*types.Pointer); isPtr {
						args.FieldViewName = it.QualifiedName(base) + "View"
						writeTemplate("viewSliceField")
					} else {
						writeTemplate("unsupportedField")
					}
					continue
				} else if shallow {
					if _, isBasic := base.(*types.Basic); isBasic {
						writeTemplate("unsupportedField")
					} else {
						args.FieldViewName = it.QualifiedName(base) + "View"
						writeTemplate("viewSliceField")
					}
					continue
				}
				writeTemplate("sliceField")
			}
			continue
		case *types.Struct, *types.Named:
			strucT := underlying
			args.FieldType = it.QualifiedName(fieldType)
			if codegen.ContainsPointers(strucT) {
				writeTemplate("viewField")
				continue
			}
			writeTemplate("valueField")
			continue
		case *types.Map:
			m := underlying
			args.FieldType = it.QualifiedName(fieldType)
			shallow, deep, key := requiresCloning(m.Key())
			if shallow || deep {
				writeTemplate("unsupportedField")
				continue
			}
			args.MapKeyType = it.QualifiedName(key)
			mElem := m.Elem()
			var template string
			switch u := mElem.(type) {
			case *types.Struct, *types.Named:
				strucT := u
				args.FieldType = it.QualifiedName(fieldType)
				if codegen.ContainsPointers(strucT) {
					args.MapFn = "t.View()"
					template = "mapFnField"
					args.MapValueType = it.QualifiedName(mElem)
					args.MapValueView = args.MapValueType + "View"
				} else {
					template = "mapField"
					args.MapValueType = it.QualifiedName(mElem)
				}
			case *types.Basic:
				template = "mapField"
				args.MapValueType = it.QualifiedName(mElem)
			case *types.Slice:
				slice := u
				sElem := slice.Elem()
				switch x := sElem.(type) {
				case *types.Basic:
					args.MapValueView = fmt.Sprintf("views.Slice[%v]", sElem)
					args.MapValueType = "[]" + sElem.String()
					args.MapFn = "views.SliceOf(t)"
					template = "mapFnField"
				case *types.Pointer:
					ptr := x
					pElem := ptr.Elem()
					switch pElem.(type) {
					case *types.Struct, *types.Named:
						ptrType := it.QualifiedName(ptr)
						viewType := it.QualifiedName(pElem) + "View"
						args.MapFn = fmt.Sprintf("views.SliceOfViews[%v,%v](t)", ptrType, viewType)
						args.MapValueView = fmt.Sprintf("views.SliceView[%v,%v]", ptrType, viewType)
						args.MapValueType = "[]" + ptrType
						template = "mapFnField"
					default:
						template = "unsupportedField"
					}
				default:
					template = "unsupportedField"
				}
			case *types.Pointer:
				ptr := u
				pElem := ptr.Elem()
				switch pElem.(type) {
				case *types.Struct, *types.Named:
					args.MapValueType = it.QualifiedName(ptr)
					args.MapValueView = it.QualifiedName(pElem) + "View"
					args.MapFn = "t.View()"
					template = "mapFnField"
				default:
					template = "unsupportedField"
				}
			default:
				template = "unsupportedField"
			}
			writeTemplate(template)
			continue
		case *types.Pointer:
			ptr := underlying
			_, deep, base := requiresCloning(ptr)
			if deep {
				args.FieldType = it.QualifiedName(base)
				writeTemplate("viewField")
			} else {
				args.FieldType = it.QualifiedName(ptr)
				writeTemplate("valuePointerField")
			}
			continue
		}
		writeTemplate("unsupportedField")
	}
	for i := 0; i < typ.NumMethods(); i++ {
		f := typ.Method(i)
		if !f.Exported() {
			continue
		}
		sig, ok := f.Type().(*types.Signature)
		if !ok {
			continue
		}

		switch f.Name() {
		case "Clone", "View":
			continue // "AsStruct"
		case "String":
			writeTemplate("stringFunc")
			continue
		case "Equal":
			if sig.Results().Len() == 1 && sig.Results().At(0).Type().String() == "bool" {
				writeTemplate("equalFunc")
				continue
			}
		}
	}
	fmt.Fprintf(buf, "\n")
	buf.Write(codegen.AssertStructUnchanged(t, args.StructName, "View", it))
}

var (
	flagTypes     = flag.String("type", "", "comma-separated list of types; required")
	flagBuildTags = flag.String("tags", "", "compiler build tags to apply")
	flagCloneFunc = flag.Bool("clonefunc", false, "add a top-level Clone func")

	flagCloneOnlyTypes = flag.String("clone-only-type", "", "comma-separated list of types (a subset of --type) that should only generate a go:generate clone line and not actual views")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("viewer: ")
	flag.Parse()
	if len(*flagTypes) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	typeNames := strings.Split(*flagTypes, ",")

	var flagArgs []string
	flagArgs = append(flagArgs, fmt.Sprintf("-clonefunc=%v", *flagCloneFunc))
	if *flagTypes != "" {
		flagArgs = append(flagArgs, "-type="+*flagTypes)
	}
	if *flagBuildTags != "" {
		flagArgs = append(flagArgs, "-tags="+*flagBuildTags)
	}
	pkg, namedTypes, err := codegen.LoadTypes(*flagBuildTags, ".")
	if err != nil {
		log.Fatal(err)
	}
	it := codegen.NewImportTracker(pkg.Types)

	cloneOnlyType := map[string]bool{}
	for _, t := range strings.Split(*flagCloneOnlyTypes, ",") {
		cloneOnlyType[t] = true
	}

	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "//go:generate go run tailscale.com/cmd/cloner  %s\n\n", strings.Join(flagArgs, " "))
	runCloner := false
	for _, typeName := range typeNames {
		if cloneOnlyType[typeName] {
			continue
		}
		typ, ok := namedTypes[typeName]
		if !ok {
			log.Fatalf("could not find type %s", typeName)
		}
		var hasClone bool
		for i, n := 0, typ.NumMethods(); i < n; i++ {
			if typ.Method(i).Name() == "Clone" {
				hasClone = true
				break
			}
		}
		if !hasClone {
			runCloner = true
		}
		genView(buf, it, typ, pkg.Types)
	}
	out := pkg.Name + "_view.go"
	if err := codegen.WritePackageFile("tailscale/cmd/viewer", pkg, out, it, buf); err != nil {
		log.Fatal(err)
	}
	if runCloner {
		// When a new package is added or when existing generated files have
		// been deleted, we might run into a case where tailscale.com/cmd/cloner
		// has not run yet. We detect this by verifying that all the structs we
		// interacted with have had Clone method already generated. If they
		// haven't we ask the caller to rerun generation again so that those get
		// generated.
		log.Printf("%v requires regeneration. Please run go generate again", pkg.Name+"_clone.go")
	}
}
