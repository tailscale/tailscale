describe=$(cd ../.. && git describe)
echo "$describe" >$3
redo-always
redo-stamp <$3
