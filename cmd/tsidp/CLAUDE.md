# Goal

- refactoring legacy/tsidp.go into server.go and smaller packages

## New layout

legacy/tsidp.go will be refactored into this new app structure:

```
tsidp-server.go
server/ - http web server and handlers
oauth/oauth.go - OAuth functionality
store/ - data persistence logic
```

## Refactoring Rules

- tests should be migrated with functionality into appropriate packages
- leave files in legacy/ alone
- add comments in new source files to location in legacy/ code it was migrated from
