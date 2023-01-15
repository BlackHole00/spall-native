rm -rf bin
mkdir bin

if [ "$1" = "release" ]; then
	odin build src -collection:formats=formats -out:bin/spall -debug -o:speed -no-bounds-check -define:GL_DEBUG=false
elif [ "$1" = "opt" ]; then
	odin build src -collection:formats=formats -out:bin/spall -debug -o:speed
else
	odin build src -collection:formats=formats -out:bin/spall -debug -keep-temp-files
fi
