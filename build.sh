rm -rf bin
mkdir bin

cp fonts/* bin/.
odin build src -collection:formats=formats -out:bin/spall -o:speed -debug -keep-temp-files -no-bounds-check
