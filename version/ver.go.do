redo-ifchange version-info.sh ver.go.in

. ./version-info.sh

sed -e "s/{LONGVER}/$VERSION_LONG/g" \
    -e "s/{SHORTVER}/$VERSION_SHORT/g" \
    -e "s/{GITCOMMIT}/$VERSION_GIT_HASH/g" \
    -e "s/{EXTRAGITCOMMIT}/$VERSION_EXTRA_HASH/g" \
    <ver.go.in >$3
