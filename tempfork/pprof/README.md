This is a fork of net/http/pprof that doesn't use init side effects
and doesn't use html/template (which ends up calling
reflect.Value.MethodByName, which disables some linker deadcode
optimizations).
