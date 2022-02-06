# go4.org/unsafe/assume-no-moving-gc

If your Go package wants to declare that it plays `unsafe` games that only
work if the Go runtime's garbage collector is not a moving collector, then add:

```go
import _ "go4.org/unsafe/assume-no-moving-gc"
```

Then your program will explode if that's no longer the case. (Users can override
the explosion with a scary sounding environment variable.)

This also gives us a way to find all the really gross unsafe packages.
