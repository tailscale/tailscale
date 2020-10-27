# --abbrev=200 is an arbitrary large number to capture the entire git
# hash without trying to compact it.
commit=$(cd ../.. && git describe --dirty --exclude "*" --always --abbrev=200)
echo "$commit" >$3
redo-always
redo-stamp <$3
