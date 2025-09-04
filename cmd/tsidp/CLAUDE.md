# Goal

- refactoring legacy/tsidp.go into server.go and smaller packages
- new packages are:
  - oauth/ - functionality
  - server/ - web server
  - store/ - data persistence to .json files on disk
  - ui/ - user interface code from legacy/ui\_\*

# refactoring guide

- tests should be migrated with functionality into appropriate packages
- leave files in legacy/ alone
- add comments in new source files to location in legacy/ code it was migrated from
