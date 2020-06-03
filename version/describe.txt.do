describe=$(cd ../.. && git describe --long)
echo "$describe" >$3
redo-always
redo-stamp <$3
