@echo off
rmdir /s /q bin
md bin

copy "..\Odin\vendor\sdl2\SDL2.dll" "bin\SDL2.dll"
copy "..\Odin\vendor\sdl2\ttf\SDL2_ttf.dll" "bin\SDL2_ttf.dll"

if "%1"=="release" (
    odin build src -collection:formats=formats -out:bin\spall.exe -debug -o:speed -no-bounds-check -subsystem:windows -define:GL_DEBUG=false
) else if "%1"=="opt" (
    odin build src -collection:formats=formats -out:bin\spall.exe -debug -o:speed
) else (
    odin build src -collection:formats=formats -out:bin\spall.exe -debug -keep-temp-files
)
