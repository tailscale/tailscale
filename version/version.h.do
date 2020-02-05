redo-ifchange long.txt short.txt
read -r long <long.txt
read -r short <short.txt

# get it into "major.minor.patch" format
ver=$(echo "$ver" | sed -e 's/-/./')

(
	printf '#define TAILSCALE_VERSION_LONG "%s"\n' "$long"
	printf '#define TAILSCALE_VERSION_SHORT "%s"\n' "$short"
) >$3
