This is a temporary fork of Go 1.13's os/exec package,
to work around https://github.com/golang/go/issues/36644.

The main modification (outside of removing some tests that require
internal-only packages to run) is:

```
commit 3c66be240f1ee1f1b5f03bed79eb0d9f8c08965a
Author: Avery Pennarun <apenwarr@gmail.com>
Date:   Sun Jan 19 03:17:30 2020 -0500

Cmd.Wait(): handle EINTR return code from os.Process.Wait().

This is probably not actually the correct fix; most likely
os.Process.Wait() itself should be fixed to retry on EINTR so that it
never leaks out of that function. But if we're going to patch a
particular module, it's safer to patch a higher-level one like os/exec
rather than the os module itself.

diff --git a/exec.go b/exec.go
index 17ef003e..5375e673 100644
--- a/exec.go
+++ b/exec.go
@@ -498,7 +498,21 @@ func (c *Cmd) Wait() error {
        }
                c.finished = true

-       state, err := c.Process.Wait()
+       var err error
+       var state *os.ProcessState
+       for {
+               state, err = c.Process.Wait()
+               if err != nil {
+                       xe, ok := err.(*os.SyscallError)
+                       if ok {
+                               if xe.Unwrap() == syscall.EINTR {
+                                       // temporary error, retry wait syscall
+                                       continue
+                               }
+                       }
+               }
+               break
+       }
        if c.waitDone != nil {
                        close(c.waitDone)
                                }
```
