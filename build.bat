@echo off
rmdir /s /q bin
md bin

copy "..\Odin\vendor\sdl2\SDL2.dll" "bin\SDL2.dll"
copy "..\Odin\vendor\sdl2\ttf\SDL2_ttf.dll" "bin\SDL2_ttf.dll"
copy "fonts\*.*" "bin"
REM odin build src -subsystem:windows -collection:formats=formats -out:bin\spall.exe -no-bounds-check -o:speed
REM odin build src -collection:formats=formats -out:bin\spall.exe -no-bounds-check -o:speed
REM odin build src -collection:formats=formats -out:bin\spall.exe -no-bounds-check -debug -o:speed -keep-temp-files
odin build src -collection:formats=formats -out:bin\spall.exe -debug -o:speed -keep-temp-files
