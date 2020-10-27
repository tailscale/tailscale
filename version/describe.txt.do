describe=$(git describe --long --abbrev=9)
echo "$describe" >$3
redo-always
redo-stamp <$3
