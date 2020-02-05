redo-ifchange ../../../version/short.txt gen-changelog
(
	cd ..
	debian/gen-changelog
) >$3
