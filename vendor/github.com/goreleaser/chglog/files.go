package chglog

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

// Parse parse a changelog.yml into ChangeLogEntries.
func Parse(file string) (entries ChangeLogEntries, err error) {
	var (
		body []byte
	)
	body, err = ioutil.ReadFile(file) // nolint: gosec,gocritic
	switch {
	case os.IsNotExist(err):
		return make(ChangeLogEntries, 0), nil
	case err != nil:
		return nil, fmt.Errorf("error parsing %s: %w", file, err)
	}

	if err = yaml.Unmarshal(body, &entries); err != nil {
		return entries, fmt.Errorf("error parsing %s: %w", file, err)
	}

	return entries, nil
}

// Save save ChangeLogEntries to a yml file.
func (c *ChangeLogEntries) Save(file string) (err error) {
	data, _ := yaml.Marshal(c)
	// nolint: gosec,gocritic
	return ioutil.WriteFile(file, data, 0644)
}
