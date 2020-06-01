redo-ifchange mkversion.sh describe.txt
read -r describe <describe.txt
ver=$(./mkversion.sh short "$describe")
echo "$ver" >$3
