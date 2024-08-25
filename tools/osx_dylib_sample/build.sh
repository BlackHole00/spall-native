clang -o same -O3 main.c
clang -dynamiclib -o same.dylib -O3 dylib_shim.c
