redo-ifchange long.txt short.txt gitcommit.txt extragitcommit.txt ver.go.in

read -r LONGVER <long.txt
read -r SHORTVER <short.txt
read -r GITCOMMIT <gitcommit.txt
read -r EXTRAGITCOMMIT <extragitcommit.txt

sed -e "s/{LONGVER}/$LONGVER/g" \
    -e "s/{SHORTVER}/$SHORTVER/g" \
    -e "s/{GITCOMMIT}/$GITCOMMIT/g" \
    -e "s/{EXTRAGITCOMMIT}/$EXTRAGITCOMMIT/g" \
    <ver.go.in >$3
