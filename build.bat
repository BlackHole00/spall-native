@echo off

taskkill /T /IM spall.exe 2>nul >nul

rmdir /s /q bin
md bin


if "%1"=="release" (
    odin build src -collection:formats=formats -out:bin\spall.exe -debug -o:speed -no-bounds-check -subsystem:windows -define:GL_DEBUG=false -resource:resources\spall.rc
) else if "%1"=="opt" (
    odin build src -collection:formats=formats -out:bin\spall.exe -debug -o:speed -resource:resources\spall.rc
) else (
    odin build src -collection:formats=formats -out:bin\spall.exe -debug -keep-temp-files -resource:resources\spall.rc
)

copy resources\SDL2.dll bin\ 2>nul >nul
copy resources\SDL2_ttf.dll bin\ 2>nul >nul
