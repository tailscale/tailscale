// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// build ignore

package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dave/jennifer/jen"
	"github.com/iancoleman/strcase"
	"tailscale.com/tstest/integration/vms"
)

func main() {
	f := jen.NewFile("vms")
	f.Comment("Code generated by tstest/integration/vms/gen/test_codegen.go DO NOT EDIT.")

	ptr := jen.Op("*")

	for i, d := range vms.Distros {
		f.Func().
			Id("TestRun" + strcase.ToCamel(d.Name)).
			Params(jen.Id("t").Add(ptr).Qual("testing", "T")).
			BlockFunc(func(g *jen.Group) {
				g.Id("t").Dot("Parallel").Call()
				g.Id("setupTests").Call(jen.Id("t"))
				g.Id("testOneDistribution").Call(jen.Id("t"), jen.Lit(i), jen.Id("Distros").Index(jen.Lit(i)))
			})
	}

	os.Remove("top_level_test.go")
	fout, err := os.Create("top_level_test.go")
	if err != nil {
		log.Fatal(err)
	}
	defer fout.Close()

	fmt.Fprintf(fout, "// Copyright (c) %d Tailscale Inc & AUTHORS All rights reserved.\n", time.Now().Year())
	fout.WriteString("// Use of this source code is governed by a BSD-style\n")
	fout.WriteString("// license that can be found in the LICENSE file.\n")
	fout.WriteString("\n")
	fout.WriteString("// +build linux\n\n")

	err = f.Render(fout)
	if err != nil {
		log.Fatal(err)
	}
}
