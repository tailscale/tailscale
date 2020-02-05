redo-ifchange long.txt
read -r LONGVER junk <long.txt

# Convert a version like "0.92-98-g123456" into "0.92-98".
# Sometimes the version is just "0.92-0", in which case we leave it as is.
case $LONGVER in
	*-*-*)
		echo "${LONGVER%-*}" >$3
		;;
	*-*)
		echo "$LONGVER" >$3
		;;
	*)
		echo "Fatal: long version in invalid format." >&2
		exit 44
esac

redo-stamp <$3
