// Command to generate DCP package source from the XML specification.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var (
	deviceURNPrefix  = "urn:schemas-upnp-org:device:"
	serviceURNPrefix = "urn:schemas-upnp-org:service:"
)

func main() {
	var (
		dcpName  = flag.String("dcp_name", "", "Name of the DCP to generate.")
		specsDir = flag.String("specs_dir", ".", "Path to the specification storage directory. "+
			"This is used to find (and download if not present) the specification ZIP files.")
		useGofmt = flag.Bool("gofmt", true, "Pass the generated code through gofmt. "+
			"Disable this if debugging code generation and needing to see the generated code "+
			"prior to being passed through gofmt.")
	)
	flag.Parse()

	if err := run(*dcpName, *specsDir, *useGofmt); err != nil {
		log.Fatal(err)
	}
}

func run(dcpName, specsDir string, useGofmt bool) error {
	if err := os.MkdirAll(specsDir, os.ModePerm); err != nil {
		return fmt.Errorf("could not create specs-dir %q: %v", specsDir, err)
	}

	for _, d := range dcpMetadata {
		if d.Name != dcpName {
			continue
		}
		specFilename := filepath.Join(specsDir, d.Name+".zip")
		err := acquireFile(specFilename, d.XMLSpecURL)
		if err != nil {
			return fmt.Errorf("could not acquire spec for %s: %v", d.Name, err)
		}
		dcp := newDCP(d)
		if err := dcp.processZipFile(specFilename); err != nil {
			return fmt.Errorf("error processing spec for %s in file %q: %v", d.Name, specFilename, err)
		}
		for i, hack := range d.Hacks {
			if err := hack(dcp); err != nil {
				return fmt.Errorf("error with Hack[%d] for %s: %v", i, d.Name, err)
			}
		}
		if err := dcp.writeCode(d.Name+".go", useGofmt); err != nil {
			return fmt.Errorf("error writing package %q: %v", dcp.Metadata.Name, err)
		}

		return nil
	}

	return fmt.Errorf("could not find DCP with name %q", dcpName)
}
