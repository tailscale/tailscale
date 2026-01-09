package identityfederation

type TokenSourceKind string

const (
	SourceUnknown TokenSourceKind = "unknown"
	SourceGitHub  TokenSourceKind = "github"
	SourceAWS     TokenSourceKind = "aws"
	SourceGCP     TokenSourceKind = "gcp"
	SourceAzure   TokenSourceKind = "azure"
)

func detectIdp() {}
