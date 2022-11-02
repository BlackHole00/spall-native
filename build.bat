@echo off
rmdir /s /q bin
md bin

copy "..\Odin\vendor\sdl2\sdl2.dll" "bin\sdl2.dll"
REM odin build src -subsystem:windows -collection:formats=formats -out:bin\spall.exe -no-bounds-check -debug -o:speed
odin build src -collection:formats=formats -out:bin\spall.exe -no-bounds-check -debug -o:speed
