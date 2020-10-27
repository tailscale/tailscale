commit=$(git describe --dirty --exclude "*" --always --abbrev=12)
echo "$commit" >$3
redo-always
redo-stamp <$3
