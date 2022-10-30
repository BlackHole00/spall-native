@echo off
rmdir bin
md bin

odin build . -out:bin/spall.exe