// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package jsonformat provides custom JSON representation for common Go types.
//
// For custom representations of [time.Time], see:
//
//   - [TimeUnix]
//   - [TimeUnixNano]
//   - [TimeRFC1123]
//
// For custom representations of [time.Duration], see:
//
//   - [DurationNano]
//   - [DurationISO8601]
//   - [DurationUnits]
//
// For custom representations of slices and maps, see:
//
//   - [SliceEmitEmpty]
//   - [MapEmitEmpty]
//
// # History and future
//
// The [github.com/go-json-experiment/json] package was
// the prototype implementation for what became [encoding/json/v2].
// That prototype originally provided a `format` tag option that allowed
// certain types to customize their exact JSON representation.
// See [github.com/go-json-experiment/json.ExperimentalSupportFormatTag].
//
// While there was widespread support for the concept of
// custom per-type formatting in encoding/json/v2, there was also concern
// about its use of a bespoke DSL to express formatting directives.
// Consequently, support for the `format` tag was removed from the initial
// release of encoding/json/v2 in Go 1.27.
//
// The hope is that "typed struct tags" (see https://go.dev/issues/74472)
// will land in a future release of Go, in which case encoding/json/v2
// will make use of typed struct tags to express formatting directives
// in a more natural way without resorting to inventing its own DSL.
//
// This package exists as an intermediate step to support custom formats
// while encoding/json/v2 currently does not directly support it.
// Once the Go standard library supports such a feature,
// existing usages of this package are expected to migrate to using
// typed struct tags to express formatting.
//
// In the future, this package may be deleted.
package jsonformat

import _ "time" // for hotlinking [time.Duration] and [time.Time]
