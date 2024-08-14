// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	"slices"
	"strings"

	"tailscale.com/util/codegen"
	"tailscale.com/util/must"
)

const viewTemplateStr = `{{define "common"}}
// View returns a readonly view of {{.StructName}}.
func (p *{{.StructName}}{{.TypeParamNames}}) View() {{.ViewName}}{{.TypeParamNames}} {
	return {{.ViewName}}{{.TypeParamNames}}{ж: p}
}

// {{.ViewName}}{{.TypeParamNames}} provides a read-only view over {{.StructName}}{{.TypeParamNames}}.
//
// Its methods should only be called if ` + "`Valid()`" + ` returns true.
type {{.ViewName}}{{.TypeParams}} struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *{{.StructName}}{{.TypeParamNames}}
}

// Valid reports whether underlying value is non-nil.
func (v {{.ViewName}}{{.TypeParamNames}}) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v {{.ViewName}}{{.TypeParamNames}}) AsStruct() *{{.StructName}}{{.TypeParamNames}}{ 
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v {{.ViewName}}{{.TypeParamNames}}) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *{{.ViewName}}{{.TypeParamNames}}) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x {{.StructName}}{{.TypeParamNames}}
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж=&x
	return nil
}

{{end}}
{{define "valueField"}}func (v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() {{.FieldType}} { return v.ж.{{.FieldName}} }
{{end}}
{{define "byteSliceField"}}func (v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() views.ByteSlice[{{.FieldType}}] { return views.ByteSliceOf(v.ж.{{.FieldName}}) }
{{end}}
{{define "sliceField"}}func (v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() views.Slice[{{.FieldType}}] { return views.SliceOf(v.ж.{{.FieldName}}) }
{{end}}
{{define "viewSliceField"}}func (v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() views.SliceView[{{.FieldType}},{{.FieldViewName}}] { return views.SliceOfViews[{{.FieldType}},{{.FieldViewName}}](v.ж.{{.FieldName}}) }
{{end}}
{{define "viewField"}}func (v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() {{.FieldViewName}} { return v.ж.{{.FieldName}}.View() }
{{end}}
{{define "makeViewField"}}func (v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() {{.FieldViewName}} { return {{.MakeViewFnName}}(&v.ж.{{.FieldName}}) }
{{end}}
{{define "valuePointerField"}}func (v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() {{.FieldType}} {
	if v.ж.{{.FieldName}} == nil {
		return nil
	}
	x := *v.ж.{{.FieldName}}
	return &x
}

{{end}}
{{define "mapField"}}
func(v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() views.Map[{{.MapKeyType}},{{.MapValueType}}] { return views.MapOf(v.ж.{{.FieldName}})}
{{end}}
{{define "mapFnField"}}
func(v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() views.MapFn[{{.MapKeyType}},{{.MapValueType}},{{.MapValueView}}] { return views.MapFnOf(v.ж.{{.FieldName}}, func (t {{.MapValueType}}) {{.MapValueView}} {
	return {{.MapFn}}
})}
{{end}}
{{define "mapSliceField"}}
func(v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() views.MapSlice[{{.MapKeyType}},{{.MapValueType}}] { return views.MapSliceOf(v.ж.{{.FieldName}}) }
{{end}}
{{define "unsupportedField"}}func(v {{.ViewName}}{{.TypeParamNames}}) {{.FieldName}}() {{.FieldType}} {panic("unsupported")}
{{end}}
{{define "stringFunc"}}func(v {{.ViewName}}{{.TypeParamNames}}) String() string { return v.ж.String() }
{{end}}
{{define "equalFunc"}}func(v {{.ViewName}}{{.TypeParamNames}}) Equal(v2 {{.ViewName}}{{.TypeParamNames}}) bool { return v.ж.Equal(v2.ж) }
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
		StructName     string
		ViewName       string
		TypeParams     string // e.g. [T constraints.Integer]
		TypeParamNames string // e.g. [T]

		FieldName     string
		FieldType     string
		FieldViewName string

		MapKeyType   string
		MapValueType string
		MapValueView string
		MapFn        string

		// MakeViewFnName is the name of the function that accepts a value and returns a readonly view of it.
		MakeViewFnName string
	}{
		StructName: typ.Obj().Name(),
		ViewName:   typ.Origin().Obj().Name() + "View",
	}

	typeParams := typ.Origin().TypeParams()
	args.TypeParams, args.TypeParamNames = codegen.FormatTypeParams(typeParams, it)

	writeTemplate := func(name string) {
		if err := viewTemplate.ExecuteTemplate(buf, name, args); err != nil {
			log.Fatal(err)
		}
	}
	writeTemplate("common")
	for i := range t.NumFields() {
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
			switch elem.String() {
			case "byte":
				args.FieldType = it.QualifiedName(fieldType)
				it.Import("tailscale.com/types/views")
				writeTemplate("byteSliceField")
			default:
				args.FieldType = it.QualifiedName(elem)
				it.Import("tailscale.com/types/views")
				shallow, deep, base := requiresCloning(elem)
				if deep {
					switch elem.Underlying().(type) {
					case *types.Pointer:
						if _, isIface := base.Underlying().(*types.Interface); !isIface {
							args.FieldViewName = appendNameSuffix(it.QualifiedName(base), "View")
							writeTemplate("viewSliceField")
						} else {
							writeTemplate("unsupportedField")
						}
						continue
					case *types.Interface:
						if viewType := viewTypeForValueType(elem); viewType != nil {
							args.FieldViewName = it.QualifiedName(viewType)
							writeTemplate("viewSliceField")
							continue
						}
					}
					writeTemplate("unsupportedField")
					continue
				} else if shallow {
					switch base.Underlying().(type) {
					case *types.Basic, *types.Interface:
						writeTemplate("unsupportedField")
					default:
						if _, isIface := base.Underlying().(*types.Interface); !isIface {
							args.FieldViewName = appendNameSuffix(it.QualifiedName(base), "View")
							writeTemplate("viewSliceField")
						} else {
							writeTemplate("unsupportedField")
						}
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
				if viewType := viewTypeForValueType(fieldType); viewType != nil {
					args.FieldViewName = it.QualifiedName(viewType)
					writeTemplate("viewField")
					continue
				}
				if viewType, makeViewFn := viewTypeForContainerType(fieldType); viewType != nil {
					args.FieldViewName = it.QualifiedName(viewType)
					args.MakeViewFnName = it.PackagePrefix(makeViewFn.Pkg()) + makeViewFn.Name()
					writeTemplate("makeViewField")
					continue
				}
				writeTemplate("unsupportedField")
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
					args.MapValueView = appendNameSuffix(args.MapValueType, "View")
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
				case *types.Basic, *types.Named:
					sElem := it.QualifiedName(sElem)
					args.MapValueView = fmt.Sprintf("views.Slice[%v]", sElem)
					args.MapValueType = sElem
					template = "mapSliceField"
				case *types.Pointer:
					ptr := x
					pElem := ptr.Elem()
					template = "unsupportedField"
					if _, isIface := pElem.Underlying().(*types.Interface); !isIface {
						switch pElem.(type) {
						case *types.Struct, *types.Named:
							ptrType := it.QualifiedName(ptr)
							viewType := appendNameSuffix(it.QualifiedName(pElem), "View")
							args.MapFn = fmt.Sprintf("views.SliceOfViews[%v,%v](t)", ptrType, viewType)
							args.MapValueView = fmt.Sprintf("views.SliceView[%v,%v]", ptrType, viewType)
							args.MapValueType = "[]" + ptrType
							template = "mapFnField"
						default:
							template = "unsupportedField"
						}
					} else {
						template = "unsupportedField"
					}
				default:
					template = "unsupportedField"
				}
			case *types.Pointer:
				ptr := u
				pElem := ptr.Elem()
				if _, isIface := pElem.Underlying().(*types.Interface); !isIface {
					switch pElem.(type) {
					case *types.Struct, *types.Named:
						args.MapValueType = it.QualifiedName(ptr)
						args.MapValueView = appendNameSuffix(it.QualifiedName(pElem), "View")
						args.MapFn = "t.View()"
						template = "mapFnField"
					default:
						template = "unsupportedField"
					}
				} else {
					template = "unsupportedField"
				}
			case *types.Interface, *types.TypeParam:
				if viewType := viewTypeForValueType(u); viewType != nil {
					args.MapValueType = it.QualifiedName(u)
					args.MapValueView = it.QualifiedName(viewType)
					args.MapFn = "t.View()"
					template = "mapFnField"
				} else if !codegen.ContainsPointers(u) {
					args.MapValueType = it.QualifiedName(mElem)
					template = "mapField"
				} else {
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
				if _, isIface := base.Underlying().(*types.Interface); !isIface {
					args.FieldType = it.QualifiedName(base)
					args.FieldViewName = appendNameSuffix(args.FieldType, "View")
					writeTemplate("viewField")
				} else {
					writeTemplate("unsupportedField")
				}
			} else {
				args.FieldType = it.QualifiedName(ptr)
				writeTemplate("valuePointerField")
			}
			continue
		case *types.Interface:
			// If fieldType is an interface with a "View() {ViewType}" method, it can be used to clone the field.
			// This includes scenarios where fieldType is a constrained type parameter.
			if viewType := viewTypeForValueType(underlying); viewType != nil {
				args.FieldViewName = it.QualifiedName(viewType)
				writeTemplate("viewField")
				continue
			}
		}
		writeTemplate("unsupportedField")
	}
	for i := range typ.NumMethods() {
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
	buf.Write(codegen.AssertStructUnchanged(t, args.StructName, typeParams, "View", it))
}

func appendNameSuffix(name, suffix string) string {
	if idx := strings.IndexRune(name, '['); idx != -1 {
		// Insert suffix after the type name, but before type parameters.
		return name[:idx] + suffix + name[idx:]
	}
	return name + suffix
}

func viewTypeForValueType(typ types.Type) types.Type {
	if ptr, ok := typ.(*types.Pointer); ok {
		return viewTypeForValueType(ptr.Elem())
	}
	viewMethod := codegen.LookupMethod(typ, "View")
	if viewMethod == nil {
		return nil
	}
	sig, ok := viewMethod.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return nil
	}
	return sig.Results().At(0).Type()
}

func viewTypeForContainerType(typ types.Type) (*types.Named, *types.Func) {
	// The container type should be an instantiated generic type,
	// with its first type parameter specifying the element type.
	containerType, ok := typ.(*types.Named)
	if !ok || containerType.TypeArgs().Len() == 0 {
		return nil, nil
	}

	// Look up the view type for the container type.
	// It must include an additional type parameter specifying the element's view type.
	// For example, Container[T] => ContainerView[T, V].
	containerViewTypeName := containerType.Obj().Name() + "View"
	containerViewTypeObj, ok := containerType.Obj().Pkg().Scope().Lookup(containerViewTypeName).(*types.TypeName)
	if !ok {
		return nil, nil
	}
	containerViewGenericType, ok := containerViewTypeObj.Type().(*types.Named)
	if !ok || containerViewGenericType.TypeParams().Len() != containerType.TypeArgs().Len()+1 {
		return nil, nil
	}

	// Create a list of type arguments for instantiating the container view type.
	// Include all type arguments specified for the container type...
	containerViewTypeArgs := make([]types.Type, containerViewGenericType.TypeParams().Len())
	for i := range containerType.TypeArgs().Len() {
		containerViewTypeArgs[i] = containerType.TypeArgs().At(i)
	}
	// ...and add the element view type.
	// For that, we need to first determine the named elem type...
	elemType, ok := baseType(containerType.TypeArgs().At(containerType.TypeArgs().Len() - 1)).(*types.Named)
	if !ok {
		return nil, nil
	}
	// ...then infer the view type from it.
	var elemViewType *types.Named
	elemTypeName := elemType.Obj().Name()
	elemViewTypeBaseName := elemType.Obj().Name() + "View"
	if elemViewTypeName, ok := elemType.Obj().Pkg().Scope().Lookup(elemViewTypeBaseName).(*types.TypeName); ok {
		// The elem's view type is already defined in the same package as the elem type.
		elemViewType = elemViewTypeName.Type().(*types.Named)
	} else if slices.Contains(typeNames, elemTypeName) {
		// The elem's view type has not been generated yet, but we can define
		// and use a blank type with the expected view type name.
		elemViewTypeName = types.NewTypeName(0, elemType.Obj().Pkg(), elemViewTypeBaseName, nil)
		elemViewType = types.NewNamed(elemViewTypeName, types.NewStruct(nil, nil), nil)
		if elemTypeParams := elemType.TypeParams(); elemTypeParams != nil {
			elemViewType.SetTypeParams(collectTypeParams(elemTypeParams))
		}
	} else {
		// The elem view type does not exist and won't be generated.
		return nil, nil
	}
	// If elemType is an instantiated generic type, instantiate the elemViewType as well.
	if elemTypeArgs := elemType.TypeArgs(); elemTypeArgs != nil {
		elemViewType = must.Get(types.Instantiate(nil, elemViewType, collectTypes(elemTypeArgs), false)).(*types.Named)
	}
	// And finally set the elemViewType as the last type argument.
	containerViewTypeArgs[len(containerViewTypeArgs)-1] = elemViewType

	// Instantiate the container view type with the specified type arguments.
	containerViewType := must.Get(types.Instantiate(nil, containerViewGenericType, containerViewTypeArgs, false))
	// Look up a function to create a view of a container.
	// It should be in the same package as the container type, named {ViewType}Of,
	// and have a signature like {ViewType}Of(c *Container[T]) ContainerView[T, V].
	makeContainerView, ok := containerType.Obj().Pkg().Scope().Lookup(containerViewTypeName + "Of").(*types.Func)
	if !ok {
		return nil, nil
	}
	return containerViewType.(*types.Named), makeContainerView
}

func baseType(typ types.Type) types.Type {
	if ptr, ok := typ.(*types.Pointer); ok {
		return ptr.Elem()
	}
	return typ
}

func collectTypes(list *types.TypeList) []types.Type {
	// TODO(nickkhyl): use slices.Collect in Go 1.23?
	if list.Len() == 0 {
		return nil
	}
	res := make([]types.Type, list.Len())
	for i := range res {
		res[i] = list.At(i)
	}
	return res
}

func collectTypeParams(list *types.TypeParamList) []*types.TypeParam {
	if list.Len() == 0 {
		return nil
	}
	res := make([]*types.TypeParam, list.Len())
	for i := range res {
		p := list.At(i)
		res[i] = types.NewTypeParam(p.Obj(), p.Constraint())
	}
	return res
}

var (
	flagTypes     = flag.String("type", "", "comma-separated list of types; required")
	flagBuildTags = flag.String("tags", "", "compiler build tags to apply")
	flagCloneFunc = flag.Bool("clonefunc", false, "add a top-level Clone func")

	flagCloneOnlyTypes = flag.String("clone-only-type", "", "comma-separated list of types (a subset of --type) that should only generate a go:generate clone line and not actual views")

	typeNames []string
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("viewer: ")
	flag.Parse()
	if len(*flagTypes) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	typeNames = strings.Split(*flagTypes, ",")

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
	out := pkg.Name + "_view"
	if *flagBuildTags == "test" {
		out += "_test"
	}
	out += ".go"
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
