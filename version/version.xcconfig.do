redo-ifchange version-info.sh

. ./version-info.sh

# CFBundleShortVersionString: the "short name" used in the App Store.
# eg. 0.92.98
echo "VERSION_NAME = $VERSION_SHORT"
# CFBundleVersion: the build number. Needs to be 3 numeric sections
# that increment for each release according to SemVer rules.
#
# We start counting at 100 because we submitted using raw build
# numbers before, and Apple doesn't let you start over.  e.g. 0.98.3
# -> 100.98.3
echo "VERSION_ID = $VERSION_XCODE"
