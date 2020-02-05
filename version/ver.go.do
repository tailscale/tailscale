redo-ifchange long.txt short.txt ver.go.in

read -r LONGVER <long.txt
read -r SHORTVER <short.txt

sed -e "s/{LONGVER}/$LONGVER/g" \
    -e "s/{SHORTVER}/$SHORTVER/g" \
    <ver.go.in >$3
