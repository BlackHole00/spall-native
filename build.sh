rm -rf bin
mkdir bin

if [ "$(uname)" == "Darwin" ]; then
    rm src/freq.a
    clang -o bin/darwin_freq.o -c src/darwin_freq.c -mmacosx-version-min=11.0
    ar rcs src/freq.a bin/darwin_freq.o
fi

if [ "$1" = "release" ]; then
	odin build src -collection:formats=formats -out:bin/spall -debug -o:speed -no-bounds-check -define:GL_DEBUG=false -strict-style -minimum-os-version:11.0
elif [ "$1" = "opt" ]; then
	odin build src -collection:formats=formats -out:bin/spall -debug -o:speed -strict-style -minimum-os-version:11.0
else
	odin build src -collection:formats=formats -out:bin/spall -debug -strict-style -minimum-os-version:11.0
fi
