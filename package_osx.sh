set -x

if [[ "$1" == "" ]]; then
	APP_PATH="./bin/spall.app"
else
	APP_PATH="$1"
fi

if [[ "$2" == "" ]]; then
	SPALL_PATH="./bin/spall"
else
	SPALL_PATH="$2"
fi

if [[ "$3" == "" ]]; then
	SDL_PATH="../SDL/out/lib/libSDL2-2.0.0.dylib"
else
	SDL_PATH="$3"
fi

rm -rf $APP_PATH
mkdir $APP_PATH
mkdir $APP_PATH/Contents
mkdir $APP_PATH/Contents/MacOS
mkdir $APP_PATH/Contents/resources
mkdir $APP_PATH/Contents/Frameworks
cp $SPALL_PATH $APP_PATH/Contents/MacOS/.
cp resources/info.plist $APP_PATH/Contents/.
cp resources/icon.icns $APP_PATH/Contents/resources/.
cp $SDL_PATH $APP_PATH/Contents/Frameworks/.

SDL_DYLIB_PATH=$(otool -L $APP_PATH/Contents/MacOS/spall | grep -m 1 "SDL" | awk -F '.dylib' '{print $1}' | awk '{$1=$1};1')
install_name_tool -change $SDL_DYLIB_PATH @executable_path/../Frameworks/libSDL2-2.0.0.dylib $APP_PATH/Contents/MacOS/spall
