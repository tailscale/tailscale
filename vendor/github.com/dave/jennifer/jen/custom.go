package jen

// Options specifies options for the Custom method
type Options struct {
	Open      string
	Close     string
	Separator string
	Multi     bool
}

// Custom renders a customized statement list. Pass in options to specify multi-line, and tokens for open, close, separator.
func Custom(options Options, statements ...Code) *Statement {
	return newStatement().Custom(options, statements...)
}

// Custom renders a customized statement list. Pass in options to specify multi-line, and tokens for open, close, separator.
func (g *Group) Custom(options Options, statements ...Code) *Statement {
	s := Custom(options, statements...)
	g.items = append(g.items, s)
	return s
}

// Custom renders a customized statement list. Pass in options to specify multi-line, and tokens for open, close, separator.
func (s *Statement) Custom(options Options, statements ...Code) *Statement {
	g := &Group{
		close:     options.Close,
		items:     statements,
		multi:     options.Multi,
		name:      "custom",
		open:      options.Open,
		separator: options.Separator,
	}
	*s = append(*s, g)
	return s
}

// CustomFunc renders a customized statement list. Pass in options to specify multi-line, and tokens for open, close, separator.
func CustomFunc(options Options, f func(*Group)) *Statement {
	return newStatement().CustomFunc(options, f)
}

// CustomFunc renders a customized statement list. Pass in options to specify multi-line, and tokens for open, close, separator.
func (g *Group) CustomFunc(options Options, f func(*Group)) *Statement {
	s := CustomFunc(options, f)
	g.items = append(g.items, s)
	return s
}

// CustomFunc renders a customized statement list. Pass in options to specify multi-line, and tokens for open, close, separator.
func (s *Statement) CustomFunc(options Options, f func(*Group)) *Statement {
	g := &Group{
		close:     options.Close,
		multi:     options.Multi,
		name:      "custom",
		open:      options.Open,
		separator: options.Separator,
	}
	f(g)
	*s = append(*s, g)
	return s
}
