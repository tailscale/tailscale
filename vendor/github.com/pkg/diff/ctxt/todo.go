package ctxt

// TODO: the standard way to reduce context is to a fixed number of lines around changes.
// But it would be better to be more flexible, to try to match human needs.
// For example, if I deleted the first line of a function, I don't need three full lines of "before" context;
// it should truncate at the function declaration.
