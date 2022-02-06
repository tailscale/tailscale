package chglog

import (
	"regexp"
	"strings"
)

// nolint:gocritic
var expectedFormatRegex = regexp.MustCompile(`(?s)^(?P<category>\S+?)?(?P<scope>\(\S+\))?(?P<breaking>!?)?: (?P<description>[^\n\r]+)?([\n\r]{2}(?P<body>.*))?`)

// ParseConventionalCommit takes a commits message and parses it into usable blocks.
func ParseConventionalCommit(message string) (commit *ConventionalCommit) {
	match := expectedFormatRegex.FindStringSubmatch(message)

	if len(match) == 0 {
		parts := strings.SplitN(message, "\n", 2)
		parts = append(parts, "")

		return &ConventionalCommit{
			Description: parts[0],
			Body:        processMsg(parts[1]),
		}
	}

	result := make(map[string]string)
	for i, name := range expectedFormatRegex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}

	scope := result["scope"]

	// strip brackets from scope if present
	if scope != "" {
		scope = strings.Replace(scope, "(", "", 1)
		scope = strings.Replace(scope, ")", "", 1)
	}

	return &ConventionalCommit{
		Category:    result["category"],
		Scope:       scope,
		Breaking:    result["breaking"] == "!" || strings.Contains(result["body"], "BREAKING CHANGE"),
		Description: result["description"],
		Body:        result["body"],
	}
}
