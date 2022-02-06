# Tagliatelle

[![Sponsor](https://img.shields.io/badge/Sponsor%20me-%E2%9D%A4%EF%B8%8F-pink)](https://github.com/sponsors/ldez)
[![Build Status](https://github.com/ldez/tagliatelle/workflows/Main/badge.svg?branch=master)](https://github.com/ldez/tagliatelle/actions)

A linter that handles struct tags.

Supported string casing:

- `camel`
- `pascal`
- `kebab`
- `smake`
- `goCamel`
- `goPascal`
- `goKebab`
- `goSmake`
- `upper`
- `lower`

## Examples

```go
// json and camel case
type Foo struct {
    ID     string `json:"ID"` // must be "id"
    UserID string `json:"UserID"`// must be "userId"
    Name   string `json:"name"`
    Value  string `json:"val,omitempty"`// must be "value"
}
```
