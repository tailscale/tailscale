package cli

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/types/geo"
)

var locationCmd = func() *ffcli.Command {
	if !envknob.UseWIPCode() {
		return nil
	}
	return &ffcli.Command{
		Name:      "location",
		Exec:      runLocation,
		ShortHelp: "Print or change location data, for testing",
		ShortUsage: "" +
			"  Print all fields:  tailscale debug location\n" +
			"  Print a field:     tailscale debug location FIELD\n" +
			"  Clear a field:     tailscale debug location FIELD=\n" +
			"  Change field[s]:   tailscale debug location FIELD=VALUE [...]",
		LongHelp: "" +
			"FIELDS\n" +
			locationFields.help(),
	}
}

func runLocation(ctx context.Context, args []string) error {
	var getks []locationGetK
	var setvs []locationSetV

	if len(args) == 0 {
		// Print all fields:
		for _, k := range slices.Sorted(maps.Keys(locationFields)) {
			getk := locationGetK{
				get: locationFields[k].get,
				k:   k,
			}
			getks = append(getks, getk)
		}
		return nil
	}

	// Parse all args first, to avoid having to abort halfway through.
	for _, arg := range args {
		k, v, set := strings.Cut(arg, "=")
		field, known := locationFields[k]
		if !known {
			return fmt.Errorf("unknown field: %s", k)
		}

		if set {
			// Change or clear these fields:
			setv := locationSetV{
				set: field.set,
				k:   k,
				v:   v,
			}
			setvs = append(setvs, setv)
		} else {
			// Print a field:
			getk := locationGetK{
				get: field.get,
				k:   k,
			}
			getks = append(getks, getk)
		}
	}

	if len(getks) > 0 && len(setvs) > 0 {
		gk, sv := getks[0], setvs[0]
		return fmt.Errorf("cannot mix %s and %s=%q", gk.k, sv.k, sv.v)
	}

	if len(setvs) > 0 {
		// Perform the change or clear:
		prefs := &ipn.MaskedPrefs{Prefs: ipn.Prefs{}}
		for _, sv := range setvs {
			if err := sv.set(prefs, sv.v); err != nil {
				return err
			}
		}
		ctx = apitype.RequestReasonKey.WithValue(ctx, "debug location")
		if _, err := localClient.EditPrefs(ctx, prefs); err != nil {
			return err
		}
		return nil
		// TODO(sfllaw): [LocalBackend.applyPrefsToHostinfoLocked]
		// [Auto.SetHostinfo]
		// [Hostinfo.RoutableIPs] corresponds to --advertise-routes
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}

	switch len(getks) {
	case 1:
		// Print one fields, without key name:
		fmt.Printf("%s", getks[0].get(prefs))
	default:
		// Print multiple fields:
		for _, gk := range getks {
			fmt.Printf("%s=%s", gk.k, gk.get(prefs))
		}
	}
	return nil
}

type locationFieldsT map[string]locationField

var locationFields = locationFieldsT{
	"city": {
		get: func(p *ipn.Prefs) string {
			return p.LocationCity
		},
		set: func(p *ipn.MaskedPrefs, v string) error {
			p.LocationCity = v
			p.LocationCitySet = true
			return nil
		},
		help: "  city=NAME\n" +
			"\tNAME of this node’s city",
	},
	"coords": {
		get: func(p *ipn.Prefs) string {
			return p.LocationCoords.FormatLatLng()
		},
		set: func(p *ipn.MaskedPrefs, v string) error {
			pt, err := geo.ParsePoint(v)
			if err != nil {
				return err
			}
			pt = pt.Quantize()

			s, err := pt.MarshalText()
			if err != nil {
				return err
			}

			p.LocationCoords = s
			p.LocationCoordsSet = true
			return nil
		},
		help: "  coords=(+|-)LATITUDE(+|-)LONGITUDE\n" +
			"\tLATITUDE and LONGITUDE for this node, in decimal degrees \"+45.5-73.6\"",
	},
	"country": {
		get: func(p *ipn.Prefs) string {
			return p.LocationCountry
		},
		set: func(p *ipn.MaskedPrefs, v string) error {
			p.LocationCountry = v
			p.LocationCountrySet = true
			return nil
		},
		help: "  country=NAME\n" +
			"\tNAME of this node’s country",
	},
}

func (lf locationFieldsT) help() string {
	var txt []string
	for _, k := range slices.Sorted(maps.Keys(lf)) {
		txt = append(txt, lf[k].help)
	}
	return strings.Join(txt, "\n")
}

type locationField struct {
	get  func(*ipn.Prefs) string
	set  func(*ipn.MaskedPrefs, string) error
	help string
}

type locationGetK struct {
	get  func(*ipn.Prefs) string
	k    string
	help string
}

type locationSetV struct {
	set func(*ipn.MaskedPrefs, string) error
	k   string
	v   string
}
