rm -rf bin
mkdir bin

odin build src -collection:formats=formats -out:bin/spall -o:speed -keep-temp-files
