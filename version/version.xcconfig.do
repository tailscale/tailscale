redo-ifchange mkversion.sh describe.txt extragitcommit.txt
read -r describe <describe.txt
read -r other <extragitcommit.txt
ver=$(./mkversion.sh xcode "$describe" "$other")
echo "$ver" >$3
