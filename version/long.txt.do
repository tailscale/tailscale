ver=$(cd ../.. && git describe | sed 's/^v//')
if [ "$ver" = "${ver%-*}" ]; then
	# no sub-version. ie. it's 0.05 and not 0.05-341
	# so add a sub-version.
	ver=$ver-0
fi
echo "$ver" >$3

redo-always
redo-stamp <$3
