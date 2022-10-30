@echo off
rmdir /s /q bin
md bin

copy "..\Odin\vendor\sdl2\sdl2.dll" "bin\sdl2.dll"
odin build src -subsystem:windows -out:bin\spall.exe
