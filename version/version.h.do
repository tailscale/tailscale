redo-ifchange long.txt short.txt
read -r long <long.txt
read -r short <short.txt

# get it into "major.minor.patch" format
ver=$(echo "$ver" | sed -e 's/-/./')

# winres is the MAJOR,MINOR,BUILD,REVISION 4-tuple used to identify
# the version of Windows binaries. We always set REVISION to 0, which
# seems to be how you map SemVer.
winres=$(echo "$short,0" | sed -e 's/\./,/g')

(
	printf '#define TAILSCALE_VERSION_LONG "%s"\n' "$long"
	printf '#define TAILSCALE_VERSION_SHORT "%s"\n' "$short"
	printf '#define TAILSCALE_VERSION_WIN_RES %s\n' "$winres"
) >$3
