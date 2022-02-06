package jen

// Do calls the provided function with the statement as a parameter. Use for
// embedding logic.
func Do(f func(*Statement)) *Statement {
	return newStatement().Do(f)
}

// Do calls the provided function with the statement as a parameter. Use for
// embedding logic.
func (g *Group) Do(f func(*Statement)) *Statement {
	s := Do(f)
	g.items = append(g.items, s)
	return s
}

// Do calls the provided function with the statement as a parameter. Use for
// embedding logic.
func (s *Statement) Do(f func(*Statement)) *Statement {
	f(s)
	return s
}
