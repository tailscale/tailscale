package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/tailscale/hujson"
)

// What is this?
// In the course of organizations, sometimes folks want to change their domains.
// This presents a challenge, as you need to rename identifiers for identities all over the place.
//
// This tool intends to help you migrate domains in two phases:
// 1. Split mode: Ensure there are always both -domain-1 and -domain-2 forms of IDs in the ACL
// 2. Trim mode: Remove all -domain-1 forms of IDs in the ACL

var (
	domain1         string
	domain2         string
	splitMode       bool
	onlySplitGroups bool
	trimMode        bool
)

func main() {
	logger := log.New(os.Stderr, "", 0)

	flag.StringVar(&domain1, "domain-1", "", "First Email Domain")
	flag.StringVar(&domain2, "domain-2", "", "Second Email Domain")
	flag.BoolVar(&splitMode, "splitDomains", false, "Ensure there are always both -domain-1 and -domain-2 forms of IDs in the ACL")
	flag.BoolVar(&onlySplitGroups, "onlySplitGroups", false, "Only split email-like IDs that start with 'group:'")
	flag.BoolVar(&trimMode, "trimDomain", false, "Remove all -domain-1 forms of IDs in the ACL")
	flag.Parse()
	if domain1 == "" || domain2 == "" {
		log.Fatal("Please provide both -domain-1 and -domain-2 flags")
	}
	if !splitMode && !trimMode {
		log.Fatal("Please provide either -splitDomains or -trimDomain flag")
	}

	// Open stdin or the first file provided as the argument to the executable.
	var err error
	var input *os.File
	if flag.NArg() == 0 {
		input = os.Stdin
	} else {
		input, err = os.Open(flag.Arg(0))
		if err != nil {
			logger.Panic("failed to open input file: %w", err)
		}
	}
	var inputBytes []byte
	buffer := make([]byte, 4096)
	for {
		n, readErr := input.Read(buffer)
		if readErr == io.EOF {
			break
		} else if readErr != nil {
			logger.Panic("failed to read input file: %w", err)
		}
		inputBytes = append(inputBytes, buffer[:n]...)
	}
	root_value, err := hujson.Parse(inputBytes)
	if err != nil {
		logger.Panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	if splitMode {
		splitDomains(&root_value)
	} else if trimMode {
		trimDomain(&root_value)
	}
	os.Stdout.WriteString(string(root_value.Pack()))
}

type Email struct {
	localPart string
	domain    string
}

func (e *Email) String() string {
	return e.localPart + "@" + e.domain
}

func otherDomain(domain string) string {
	if domain == domain1 {
		return domain2
	} else if domain == domain2 {
		return domain1
	}
	panic("unknown domain")
}

func ourDomain(domain string) bool {
	return domain == domain1 || domain == domain2
}

func toEmail(email string) (*Email, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email address: %s", email)
	}
	domain := parts[1]
	if ourDomain(domain) {
		return &Email{parts[0], domain}, nil
	}
	return nil, fmt.Errorf("domain not in list of domains to split: %s", domain)
}

func splitDomains(v *hujson.Value) {
	switch v2 := v.Value.(type) {
	case *hujson.Object:
		for i := range v2.Members {
			splitDomains(&v2.Members[i].Value)
		}
	case *hujson.Array:
		allStrings := true
		for _, elem := range v2.Elements {
			switch elem.Value.(type) {
			case hujson.Literal:
				if elem.Value.Kind() == '"' {
					allStrings = true
				} else {
					allStrings = false
					break
				}
			default:
				allStrings = false
				break
			}
		}
		if !allStrings {
			for i := range v2.Elements {
				splitDomains(&v2.Elements[i])
			}
		} else {
			// Create a map to store email-like strings
			emailMap := make(map[Email]bool)
			// First pass: build the map
			for _, str := range v2.Elements {
				email, err := toEmail(str.Value.(hujson.Literal).String())
				if err != nil {
					continue // Skip invalid email strings
				}
				emailMap[*email] = true
			}
			// Second pass: check and conditionally insert "other" domain versions
			size := len(v2.Elements)
			i := 0
			for {
				if i >= size {
					break
				}
				email, err := toEmail(v2.Elements[i].Value.(hujson.Literal).String())
				if err != nil {
					i++
					continue
				}
				if ourDomain(email.domain) {
					otherEmail := Email{localPart: email.localPart, domain: otherDomain(email.domain)}
					if !emailMap[otherEmail] {
						if onlySplitGroups && !strings.HasPrefix(email.localPart, "group:") {
							i++
							continue
						}
						v2.Elements = append(v2.Elements, hujson.ArrayElement{})
						copy(v2.Elements[i+2:], v2.Elements[i+1:])
						v2.Elements[i+1] = v2.Elements[i].Clone()
						v2.Elements[i].Value = hujson.String(otherEmail.String())
						i = i + 2
						size++
						continue
					}
				}
				i++
			}
		}
	}
}

func trimDomain(v *hujson.Value) {
	switch v2 := v.Value.(type) {
	case *hujson.Object:
		for i := range v2.Members {
			trimDomain(&v2.Members[i].Value)
		}
	case *hujson.Array:
		allStrings := true
		for _, elem := range v2.Elements {
			switch elem.Value.(type) {
			case hujson.Literal:
				if elem.Value.Kind() == '"' {
					allStrings = true
				} else {
					allStrings = false
				}
			default:
				allStrings = false
			}
		}
		if !allStrings {
			for i := range v2.Elements {
				trimDomain(&v2.Elements[i])
			}
		} else {
			size := len(v2.Elements)
			i := 0
			for {
				if i >= size {
					break
				}
				email, err := toEmail(v2.Elements[i].Value.(hujson.Literal).String())
				if err != nil {
					i++
					continue // Skip invalid email strings
				}
				if email.domain == domain1 {
					v2.Elements = append(v2.Elements[:i], v2.Elements[i+1:]...)
					size--
					continue
				}
				i++
			}
		}
	}
}
