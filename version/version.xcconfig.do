redo-ifchange short.txt
read -r ver <short.txt

# get it into "major.minor.patch" format
ver=$(echo "$ver" | sed -e 's/-/./')

# CFBundleShortVersionString: the "short name" used in the App Store.
# eg. 0.92.98
echo "VERSION_NAME = $ver" >$3
# CFBundleVersion: the build number. Needs to increment each release.
# start counting at 100 because we submitted using raw build numbers
# before (and Apple doesn't let you start over).
# eg. 100.92.98

major=$((${ver%%.*} + 100))
minor=${ver#*.}
echo "VERSION_ID = $major.$minor" >>$3
