package config

import "github.com/pkg/errors"

var defaultLintersSettings = LintersSettings{
	Lll: LllSettings{
		LineLength: 120,
		TabWidth:   1,
	},
	Unparam: UnparamSettings{
		Algo: "cha",
	},
	Nakedret: NakedretSettings{
		MaxFuncLines: 30,
	},
	Prealloc: PreallocSettings{
		Simple:     true,
		RangeLoops: true,
		ForLoops:   false,
	},
	Gocritic: GocriticSettings{
		SettingsPerCheck: map[string]GocriticCheckSettings{},
	},
	Godox: GodoxSettings{
		Keywords: []string{},
	},
	Dogsled: DogsledSettings{
		MaxBlankIdentifiers: 2,
	},
	Gocognit: GocognitSettings{
		MinComplexity: 30,
	},
	WSL: WSLSettings{
		StrictAppend:                     true,
		AllowAssignAndCallCuddle:         true,
		AllowAssignAndAnythingCuddle:     false,
		AllowMultiLineAssignCuddle:       true,
		AllowCuddleDeclaration:           false,
		AllowTrailingComment:             false,
		AllowSeparatedLeadingComment:     false,
		ForceCuddleErrCheckAndAssign:     false,
		ForceExclusiveShortDeclarations:  false,
		ForceCaseTrailingWhitespaceLimit: 0,
	},
	NoLintLint: NoLintLintSettings{
		RequireExplanation: false,
		AllowLeadingSpace:  true,
		RequireSpecific:    false,
		AllowUnused:        false,
	},
	Testpackage: TestpackageSettings{
		SkipRegexp: `(export|internal)_test\.go`,
	},
	Nestif: NestifSettings{
		MinComplexity: 5,
	},
	Exhaustive: ExhaustiveSettings{
		CheckGenerated:             false,
		DefaultSignifiesExhaustive: false,
	},
	Gofumpt: GofumptSettings{
		LangVersion: "",
		ExtraRules:  false,
	},
	ErrorLint: ErrorLintSettings{
		Errorf:     true,
		Asserts:    true,
		Comparison: true,
	},
	Ifshort: IfshortSettings{
		MaxDeclLines: 1,
		MaxDeclChars: 30,
	},
	Predeclared: PredeclaredSettings{
		Ignore:    "",
		Qualified: false,
	},
	Forbidigo: ForbidigoSettings{
		ExcludeGodocExamples: true,
	},
}

type LintersSettings struct {
	Cyclop           Cyclop
	Depguard         DepGuardSettings
	Dogsled          DogsledSettings
	Dupl             DuplSettings
	Errcheck         ErrcheckSettings
	ErrorLint        ErrorLintSettings
	Exhaustive       ExhaustiveSettings
	ExhaustiveStruct ExhaustiveStructSettings
	Forbidigo        ForbidigoSettings
	Funlen           FunlenSettings
	Gci              GciSettings
	Gocognit         GocognitSettings
	Goconst          GoConstSettings
	Gocritic         GocriticSettings
	Gocyclo          GoCycloSettings
	Godot            GodotSettings
	Godox            GodoxSettings
	Gofmt            GoFmtSettings
	Gofumpt          GofumptSettings
	Goheader         GoHeaderSettings
	Goimports        GoImportsSettings
	Golint           GoLintSettings
	Gomnd            GoMndSettings
	GoModDirectives  GoModDirectivesSettings
	Gomodguard       GoModGuardSettings
	Gosec            GoSecSettings
	Gosimple         StaticCheckSettings
	Govet            GovetSettings
	Ifshort          IfshortSettings
	Ireturn          IreturnSettings
	ImportAs         ImportAsSettings
	Lll              LllSettings
	Makezero         MakezeroSettings
	Maligned         MalignedSettings
	Misspell         MisspellSettings
	Nakedret         NakedretSettings
	Nestif           NestifSettings
	NilNil           NilNilSettings
	Nlreturn         NlreturnSettings
	NoLintLint       NoLintLintSettings
	Prealloc         PreallocSettings
	Predeclared      PredeclaredSettings
	Promlinter       PromlinterSettings
	Revive           ReviveSettings
	RowsErrCheck     RowsErrCheckSettings
	Staticcheck      StaticCheckSettings
	Structcheck      StructCheckSettings
	Stylecheck       StaticCheckSettings
	Tagliatelle      TagliatelleSettings
	Testpackage      TestpackageSettings
	Thelper          ThelperSettings
	Tenv             TenvSettings
	Unparam          UnparamSettings
	Unused           StaticCheckSettings
	Varcheck         VarCheckSettings
	Varnamelen       VarnamelenSettings
	Whitespace       WhitespaceSettings
	Wrapcheck        WrapcheckSettings
	WSL              WSLSettings

	Custom map[string]CustomLinterSettings
}

type Cyclop struct {
	MaxComplexity  int     `mapstructure:"max-complexity"`
	PackageAverage float64 `mapstructure:"package-average"`
	SkipTests      bool    `mapstructure:"skip-tests"`
}

type DepGuardSettings struct {
	ListType                 string `mapstructure:"list-type"`
	Packages                 []string
	IncludeGoRoot            bool              `mapstructure:"include-go-root"`
	PackagesWithErrorMessage map[string]string `mapstructure:"packages-with-error-message"`
}

type DogsledSettings struct {
	MaxBlankIdentifiers int `mapstructure:"max-blank-identifiers"`
}

type DuplSettings struct {
	Threshold int
}

type ErrcheckSettings struct {
	CheckTypeAssertions bool     `mapstructure:"check-type-assertions"`
	CheckAssignToBlank  bool     `mapstructure:"check-blank"`
	Ignore              string   `mapstructure:"ignore"`
	ExcludeFunctions    []string `mapstructure:"exclude-functions"`

	// Deprecated: use ExcludeFunctions instead
	Exclude string `mapstructure:"exclude"`
}

type ErrorLintSettings struct {
	Errorf     bool `mapstructure:"errorf"`
	Asserts    bool `mapstructure:"asserts"`
	Comparison bool `mapstructure:"comparison"`
}

type ExhaustiveSettings struct {
	CheckGenerated             bool   `mapstructure:"check-generated"`
	DefaultSignifiesExhaustive bool   `mapstructure:"default-signifies-exhaustive"`
	IgnorePattern              string `mapstructure:"ignore-pattern"`
}

type ExhaustiveStructSettings struct {
	StructPatterns []string `mapstructure:"struct-patterns"`
}

type IreturnSettings struct {
	Allow  []string `mapstructure:"allow"`
	Reject []string `mapstructure:"reject"`
}

type ForbidigoSettings struct {
	Forbid               []string `mapstructure:"forbid"`
	ExcludeGodocExamples bool     `mapstructure:"exclude-godoc-examples"`
}

type FunlenSettings struct {
	Lines      int
	Statements int
}

type GciSettings struct {
	LocalPrefixes string `mapstructure:"local-prefixes"`
}

type GocognitSettings struct {
	MinComplexity int `mapstructure:"min-complexity"`
}

type GoConstSettings struct {
	IgnoreTests         bool `mapstructure:"ignore-tests"`
	MatchWithConstants  bool `mapstructure:"match-constant"`
	MinStringLen        int  `mapstructure:"min-len"`
	MinOccurrencesCount int  `mapstructure:"min-occurrences"`
	ParseNumbers        bool `mapstructure:"numbers"`
	NumberMin           int  `mapstructure:"min"`
	NumberMax           int  `mapstructure:"max"`
	IgnoreCalls         bool `mapstructure:"ignore-calls"`
}

type GoCycloSettings struct {
	MinComplexity int `mapstructure:"min-complexity"`
}

type GodotSettings struct {
	Scope   string   `mapstructure:"scope"`
	Exclude []string `mapstructure:"exclude"`
	Capital bool     `mapstructure:"capital"`

	// Deprecated: use `Scope` instead
	CheckAll bool `mapstructure:"check-all"`
}

type GodoxSettings struct {
	Keywords []string
}

type GoFmtSettings struct {
	Simplify bool
}

type GofumptSettings struct {
	LangVersion string `mapstructure:"lang-version"`
	ExtraRules  bool   `mapstructure:"extra-rules"`
}

type GoHeaderSettings struct {
	Values       map[string]map[string]string `mapstructure:"values"`
	Template     string                       `mapstructure:"template"`
	TemplatePath string                       `mapstructure:"template-path"`
}

type GoImportsSettings struct {
	LocalPrefixes string `mapstructure:"local-prefixes"`
}

type GoLintSettings struct {
	MinConfidence float64 `mapstructure:"min-confidence"`
}

type GoMndSettings struct {
	Settings map[string]map[string]interface{}
}

type GoModDirectivesSettings struct {
	ReplaceAllowList          []string `mapstructure:"replace-allow-list"`
	ReplaceLocal              bool     `mapstructure:"replace-local"`
	ExcludeForbidden          bool     `mapstructure:"exclude-forbidden"`
	RetractAllowNoExplanation bool     `mapstructure:"retract-allow-no-explanation"`
}

type GoModGuardSettings struct {
	Allowed struct {
		Modules []string `mapstructure:"modules"`
		Domains []string `mapstructure:"domains"`
	} `mapstructure:"allowed"`
	Blocked struct {
		Modules []map[string]struct {
			Recommendations []string `mapstructure:"recommendations"`
			Reason          string   `mapstructure:"reason"`
		} `mapstructure:"modules"`
		Versions []map[string]struct {
			Version string `mapstructure:"version"`
			Reason  string `mapstructure:"reason"`
		} `mapstructure:"versions"`
		LocalReplaceDirectives bool `mapstructure:"local_replace_directives"`
	} `mapstructure:"blocked"`
}

type GoSecSettings struct {
	Includes         []string
	Excludes         []string
	Severity         string
	Confidence       string
	ExcludeGenerated bool                   `mapstructure:"exclude-generated"`
	Config           map[string]interface{} `mapstructure:"config"`
}

type GovetSettings struct {
	CheckShadowing bool `mapstructure:"check-shadowing"`
	Settings       map[string]map[string]interface{}

	Enable     []string
	Disable    []string
	EnableAll  bool `mapstructure:"enable-all"`
	DisableAll bool `mapstructure:"disable-all"`
}

func (cfg GovetSettings) Validate() error {
	if cfg.EnableAll && cfg.DisableAll {
		return errors.New("enable-all and disable-all can't be combined")
	}
	if cfg.EnableAll && len(cfg.Enable) != 0 {
		return errors.New("enable-all and enable can't be combined")
	}
	if cfg.DisableAll && len(cfg.Disable) != 0 {
		return errors.New("disable-all and disable can't be combined")
	}
	return nil
}

type IfshortSettings struct {
	MaxDeclLines int `mapstructure:"max-decl-lines"`
	MaxDeclChars int `mapstructure:"max-decl-chars"`
}

type ImportAsSettings struct {
	Alias       []ImportAsAlias
	NoUnaliased bool `mapstructure:"no-unaliased"`
}

type ImportAsAlias struct {
	Pkg   string
	Alias string
}

type LllSettings struct {
	LineLength int `mapstructure:"line-length"`
	TabWidth   int `mapstructure:"tab-width"`
}

type MakezeroSettings struct {
	Always bool
}

type MalignedSettings struct {
	SuggestNewOrder bool `mapstructure:"suggest-new"`
}

type MisspellSettings struct {
	Locale      string
	IgnoreWords []string `mapstructure:"ignore-words"`
}

type NakedretSettings struct {
	MaxFuncLines int `mapstructure:"max-func-lines"`
}

type NestifSettings struct {
	MinComplexity int `mapstructure:"min-complexity"`
}

type NilNilSettings struct {
	CheckedTypes []string `mapstructure:"checked-types"`
}

type NlreturnSettings struct {
	BlockSize int `mapstructure:"block-size"`
}

type NoLintLintSettings struct {
	RequireExplanation bool     `mapstructure:"require-explanation"`
	AllowLeadingSpace  bool     `mapstructure:"allow-leading-space"`
	RequireSpecific    bool     `mapstructure:"require-specific"`
	AllowNoExplanation []string `mapstructure:"allow-no-explanation"`
	AllowUnused        bool     `mapstructure:"allow-unused"`
}

type PreallocSettings struct {
	Simple     bool
	RangeLoops bool `mapstructure:"range-loops"`
	ForLoops   bool `mapstructure:"for-loops"`
}

type PredeclaredSettings struct {
	Ignore    string `mapstructure:"ignore"`
	Qualified bool   `mapstructure:"q"`
}

type PromlinterSettings struct {
	Strict          bool     `mapstructure:"strict"`
	DisabledLinters []string `mapstructure:"disabled-linters"`
}

type ReviveSettings struct {
	IgnoreGeneratedHeader bool `mapstructure:"ignore-generated-header"`
	Confidence            float64
	Severity              string
	EnableAllRules        bool `mapstructure:"enable-all-rules"`
	Rules                 []struct {
		Name      string
		Arguments []interface{}
		Severity  string
		Disabled  bool
	}
	ErrorCode   int `mapstructure:"error-code"`
	WarningCode int `mapstructure:"warning-code"`
	Directives  []struct {
		Name     string
		Severity string
	}
}

type RowsErrCheckSettings struct {
	Packages []string
}

type StaticCheckSettings struct {
	GoVersion string `mapstructure:"go"`

	Checks                  []string `mapstructure:"checks"`
	Initialisms             []string `mapstructure:"initialisms"`                // only for stylecheck
	DotImportWhitelist      []string `mapstructure:"dot-import-whitelist"`       // only for stylecheck
	HTTPStatusCodeWhitelist []string `mapstructure:"http-status-code-whitelist"` // only for stylecheck
}

func (s *StaticCheckSettings) HasConfiguration() bool {
	return len(s.Initialisms) > 0 || len(s.HTTPStatusCodeWhitelist) > 0 || len(s.DotImportWhitelist) > 0 || len(s.Checks) > 0
}

type StructCheckSettings struct {
	CheckExportedFields bool `mapstructure:"exported-fields"`
}

type TagliatelleSettings struct {
	Case struct {
		Rules        map[string]string
		UseFieldName bool `mapstructure:"use-field-name"`
	}
}

type TestpackageSettings struct {
	SkipRegexp string `mapstructure:"skip-regexp"`
}

type ThelperSettings struct {
	Test struct {
		First bool `mapstructure:"first"`
		Name  bool `mapstructure:"name"`
		Begin bool `mapstructure:"begin"`
	} `mapstructure:"test"`
	Benchmark struct {
		First bool `mapstructure:"first"`
		Name  bool `mapstructure:"name"`
		Begin bool `mapstructure:"begin"`
	} `mapstructure:"benchmark"`
	TB struct {
		First bool `mapstructure:"first"`
		Name  bool `mapstructure:"name"`
		Begin bool `mapstructure:"begin"`
	} `mapstructure:"tb"`
}

type TenvSettings struct {
	All bool `mapstructure:"all"`
}

type UnparamSettings struct {
	CheckExported bool `mapstructure:"check-exported"`
	Algo          string
}

type VarCheckSettings struct {
	CheckExportedFields bool `mapstructure:"exported-fields"`
}

type VarnamelenSettings struct {
	MaxDistance   int      `mapstructure:"max-distance"`
	MinNameLength int      `mapstructure:"min-name-length"`
	CheckReceiver bool     `mapstructure:"check-receiver"`
	CheckReturn   bool     `mapstructure:"check-return"`
	IgnoreNames   []string `mapstructure:"ignore-names"`
}

type WhitespaceSettings struct {
	MultiIf   bool `mapstructure:"multi-if"`
	MultiFunc bool `mapstructure:"multi-func"`
}

type WrapcheckSettings struct {
	IgnoreSigs         []string `mapstructure:"ignoreSigs"`
	IgnorePackageGlobs []string `mapstructure:"ignorePackageGlobs"`
}

type WSLSettings struct {
	StrictAppend                     bool `mapstructure:"strict-append"`
	AllowAssignAndCallCuddle         bool `mapstructure:"allow-assign-and-call"`
	AllowAssignAndAnythingCuddle     bool `mapstructure:"allow-assign-and-anything"`
	AllowMultiLineAssignCuddle       bool `mapstructure:"allow-multiline-assign"`
	AllowCuddleDeclaration           bool `mapstructure:"allow-cuddle-declarations"`
	AllowTrailingComment             bool `mapstructure:"allow-trailing-comment"`
	AllowSeparatedLeadingComment     bool `mapstructure:"allow-separated-leading-comment"`
	ForceCuddleErrCheckAndAssign     bool `mapstructure:"force-err-cuddling"`
	ForceExclusiveShortDeclarations  bool `mapstructure:"force-short-decl-cuddling"`
	ForceCaseTrailingWhitespaceLimit int  `mapstructure:"force-case-trailing-whitespace"`
}

// CustomLinterSettings encapsulates the meta-data of a private linter.
// For example, a private linter may be added to the golangci config file as shown below.
//
// linters-settings:
//  custom:
//    example:
//      path: /example.so
//      description: The description of the linter
//      original-url: github.com/golangci/example-linter
type CustomLinterSettings struct {
	// Path to a plugin *.so file that implements the private linter.
	Path string
	// Description describes the purpose of the private linter.
	Description string
	// The URL containing the source code for the private linter.
	OriginalURL string `mapstructure:"original-url"`
}
