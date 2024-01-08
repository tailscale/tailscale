// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cli provides the skeleton of a CLI for building release packages.
package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/clientupdate/distsign"
	"tailscale.com/release/dist"
)

// CLI returns a CLI root command to build release packages.
//
// getTargets is a function that gets run in the Exec function of commands that
// need to know the target list. Its execution is deferred in this way to allow
// customization of command FlagSets with flags that influence the target list.
func CLI(getTargets func() ([]dist.Target, error)) *ffcli.Command {
	return &ffcli.Command{
		Name:       "dist",
		ShortUsage: "dist [flags] <command> [command flags]",
		ShortHelp:  "Build tailscale release packages for distribution",
		LongHelp:   `For help on subcommands, add --help after: "dist list --help".`,
		Subcommands: []*ffcli.Command{
			{
				Name: "list",
				Exec: func(ctx context.Context, args []string) error {
					targets, err := getTargets()
					if err != nil {
						return err
					}
					return runList(ctx, args, targets)
				},
				ShortUsage: "dist list [target filters]",
				ShortHelp:  "List all available release targets.",
				LongHelp: strings.TrimSpace(`
			If filters are provided, only targets matching at least one filter are listed.
			Filters can use glob patterns (* and ?).
			`),
			},
			{
				Name: "build",
				Exec: func(ctx context.Context, args []string) error {
					targets, err := getTargets()
					if err != nil {
						return err
					}
					return runBuild(ctx, args, targets)
				},
				ShortUsage: "dist build [target filters]",
				ShortHelp:  "Build release files",
				FlagSet: (func() *flag.FlagSet {
					fs := flag.NewFlagSet("build", flag.ExitOnError)
					fs.StringVar(&buildArgs.manifest, "manifest", "", "manifest file to write")
					fs.BoolVar(&buildArgs.verbose, "verbose", false, "verbose logging")
					fs.StringVar(&buildArgs.webClientRoot, "web-client-root", "", "path to root of web client source to build")
					return fs
				})(),
				LongHelp: strings.TrimSpace(`
			If filters are provided, only targets matching at least one filter are built.
			Filters can use glob patterns (* and ?).
			`),
			},
			{
				Name: "gen-key",
				Exec: func(ctx context.Context, args []string) error {
					return runGenKey(ctx)
				},
				ShortUsage: "dist gen-key",
				ShortHelp:  "Generate root or signing key pair",
				FlagSet: (func() *flag.FlagSet {
					fs := flag.NewFlagSet("gen-key", flag.ExitOnError)
					fs.BoolVar(&genKeyArgs.root, "root", false, "generate a root key")
					fs.BoolVar(&genKeyArgs.signing, "signing", false, "generate a signing key")
					fs.StringVar(&genKeyArgs.privPath, "priv-path", "private-key.pem", "output path for the private key")
					fs.StringVar(&genKeyArgs.pubPath, "pub-path", "public-key.pem", "output path for the public key")
					return fs
				})(),
			},
			{
				Name: "sign-key",
				Exec: func(ctx context.Context, args []string) error {
					return runSignKey(ctx)
				},
				ShortUsage: "dist sign-key",
				ShortHelp:  "Sign signing keys with a root key",
				FlagSet: (func() *flag.FlagSet {
					fs := flag.NewFlagSet("sign-key", flag.ExitOnError)
					fs.StringVar(&signKeyArgs.rootPrivPath, "root-priv-path", "root-private-key.pem", "path to the root private key to sign with")
					fs.StringVar(&signKeyArgs.signPubPath, "sign-pub-path", "signing-public-keys.pem", "path to the signing public key bundle to sign; the bundle should include all active signing keys")
					fs.StringVar(&signKeyArgs.sigPath, "sig-path", "signature.bin", "oputput path for the signature")
					return fs
				})(),
			},
			{
				Name: "verify-key-signature",
				Exec: func(ctx context.Context, args []string) error {
					return runVerifyKeySignature(ctx)
				},
				ShortUsage: "dist verify-key-signature",
				ShortHelp:  "Verify a root signture of the signing keys' bundle",
				FlagSet: (func() *flag.FlagSet {
					fs := flag.NewFlagSet("verify-key-signature", flag.ExitOnError)
					fs.StringVar(&verifyKeySignatureArgs.rootPubPath, "root-pub-path", "root-public-key.pem", "path to the root public key; this can be a bundle of multiple keys")
					fs.StringVar(&verifyKeySignatureArgs.signPubPath, "sign-pub-path", "", "path to the signing public key bundle that was signed")
					fs.StringVar(&verifyKeySignatureArgs.sigPath, "sig-path", "signature.bin", "path to the signature file")
					return fs
				})(),
			},
			{
				Name: "verify-package-signature",
				Exec: func(ctx context.Context, args []string) error {
					return runVerifyPackageSignature(ctx)
				},
				ShortUsage: "dist verify-package-signature",
				ShortHelp:  "Verify a package signture using a signing key",
				FlagSet: (func() *flag.FlagSet {
					fs := flag.NewFlagSet("verify-package-signature", flag.ExitOnError)
					fs.StringVar(&verifyPackageSignatureArgs.signPubPath, "sign-pub-path", "signing-public-key.pem", "path to the signing public key; this can be a bundle of multiple keys")
					fs.StringVar(&verifyPackageSignatureArgs.packagePath, "package-path", "", "path to the package that was signed")
					fs.StringVar(&verifyPackageSignatureArgs.sigPath, "sig-path", "signature.bin", "path to the signature file")
					return fs
				})(),
			},
		},
		Exec: func(context.Context, []string) error { return flag.ErrHelp },
	}
}

func runList(ctx context.Context, filters []string, targets []dist.Target) error {
	if len(filters) == 0 {
		filters = []string{"all"}
	}
	tgts, err := dist.FilterTargets(targets, filters)
	if err != nil {
		return err
	}
	for _, tgt := range tgts {
		fmt.Println(tgt)
	}
	return nil
}

var buildArgs struct {
	manifest      string
	verbose       bool
	webClientRoot string
}

func runBuild(ctx context.Context, filters []string, targets []dist.Target) error {
	tgts, err := dist.FilterTargets(targets, filters)
	if err != nil {
		return err
	}
	if len(tgts) == 0 {
		return errors.New("no targets matched (did you mean 'dist build all'?)")
	}

	st := time.Now()
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}
	b, err := dist.NewBuild(wd, filepath.Join(wd, "dist"))
	if err != nil {
		return fmt.Errorf("creating build context: %w", err)
	}
	defer b.Close()
	b.Verbose = buildArgs.verbose
	b.WebClientSource = buildArgs.webClientRoot

	out, err := b.Build(tgts)
	if err != nil {
		return fmt.Errorf("building targets: %w", err)
	}

	if buildArgs.manifest != "" {
		// Make the built paths relative to the manifest file.
		manifest, err := filepath.Abs(buildArgs.manifest)
		if err != nil {
			return fmt.Errorf("getting absolute path of manifest: %w", err)
		}
		for i := range out {
			if !filepath.IsAbs(out[i]) {
				out[i] = filepath.Join(b.Out, out[i])
			}
			rel, err := filepath.Rel(filepath.Dir(manifest), out[i])
			if err != nil {
				return fmt.Errorf("making path relative: %w", err)
			}
			out[i] = rel
		}
		if err := os.WriteFile(manifest, []byte(strings.Join(out, "\n")), 0644); err != nil {
			return fmt.Errorf("writing manifest: %w", err)
		}
	}

	fmt.Println("Done! Took", time.Since(st))
	return nil
}

var genKeyArgs struct {
	root     bool
	signing  bool
	privPath string
	pubPath  string
}

func runGenKey(ctx context.Context) error {
	var pub, priv []byte
	var err error
	switch {
	case genKeyArgs.root && genKeyArgs.signing:
		return errors.New("only one of --root or --signing can be set")
	case !genKeyArgs.root && !genKeyArgs.signing:
		return errors.New("set either --root or --signing")
	case genKeyArgs.root:
		priv, pub, err = distsign.GenerateRootKey()
	case genKeyArgs.signing:
		priv, pub, err = distsign.GenerateSigningKey()
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(genKeyArgs.privPath, priv, 0400); err != nil {
		return fmt.Errorf("failed writing private key: %w", err)
	}
	fmt.Println("wrote private key to", genKeyArgs.privPath)
	if err := os.WriteFile(genKeyArgs.pubPath, pub, 0400); err != nil {
		return fmt.Errorf("failed writing public key: %w", err)
	}
	fmt.Println("wrote public key to", genKeyArgs.pubPath)
	return nil
}

var signKeyArgs struct {
	rootPrivPath string
	signPubPath  string
	sigPath      string
}

func runSignKey(ctx context.Context) error {
	rkRaw, err := os.ReadFile(signKeyArgs.rootPrivPath)
	if err != nil {
		return err
	}
	rk, err := distsign.ParseRootKey(rkRaw)
	if err != nil {
		return err
	}

	bundle, err := os.ReadFile(signKeyArgs.signPubPath)
	if err != nil {
		return err
	}
	sig, err := rk.SignSigningKeys(bundle)
	if err != nil {
		return err
	}

	if err := os.WriteFile(signKeyArgs.sigPath, sig, 0400); err != nil {
		return fmt.Errorf("failed writing signature file: %w", err)
	}
	fmt.Println("wrote signature to", signKeyArgs.sigPath)
	return nil
}

var verifyKeySignatureArgs struct {
	rootPubPath string
	signPubPath string
	sigPath     string
}

func runVerifyKeySignature(ctx context.Context) error {
	args := verifyKeySignatureArgs
	rootPubBundle, err := os.ReadFile(args.rootPubPath)
	if err != nil {
		return err
	}
	rootPubs, err := distsign.ParseRootKeyBundle(rootPubBundle)
	if err != nil {
		return fmt.Errorf("parsing %q: %w", args.rootPubPath, err)
	}
	signPubBundle, err := os.ReadFile(args.signPubPath)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(args.sigPath)
	if err != nil {
		return err
	}
	if !distsign.VerifyAny(rootPubs, signPubBundle, sig) {
		return errors.New("signature not valid")
	}
	fmt.Println("signature ok")
	return nil
}

var verifyPackageSignatureArgs struct {
	signPubPath string
	packagePath string
	sigPath     string
}

func runVerifyPackageSignature(ctx context.Context) error {
	args := verifyPackageSignatureArgs
	signPubBundle, err := os.ReadFile(args.signPubPath)
	if err != nil {
		return err
	}
	signPubs, err := distsign.ParseSigningKeyBundle(signPubBundle)
	if err != nil {
		return fmt.Errorf("parsing %q: %w", args.signPubPath, err)
	}
	pkg, err := os.Open(args.packagePath)
	if err != nil {
		return err
	}
	defer pkg.Close()
	pkgHash := distsign.NewPackageHash()
	if _, err := io.Copy(pkgHash, pkg); err != nil {
		return fmt.Errorf("reading %q: %w", args.packagePath, err)
	}
	hash := binary.LittleEndian.AppendUint64(pkgHash.Sum(nil), uint64(pkgHash.Len()))
	sig, err := os.ReadFile(args.sigPath)
	if err != nil {
		return err
	}
	if !distsign.VerifyAny(signPubs, hash, sig) {
		return errors.New("signature not valid")
	}
	fmt.Println("signature ok")
	return nil
}
