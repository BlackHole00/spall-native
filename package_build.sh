rm -rf spall_pkg
rm -rf spall_native_*.zip
mkdir spall_pkg
cp resources/FiraCode_LICENSE.txt spall_pkg/.
cp resources/LICENSE.txt          spall_pkg/.
cp resources/SDL2.dll             spall_pkg/.
cp resources/SDL2_ttf.dll         spall_pkg/.
cp resources/demo_trace.json      spall_pkg/.
cp resources/README.txt           spall_pkg/.
cp spall_native_auto.h            spall_pkg/.
cp ../spall-web/spall.h           spall_pkg/.
mkdir spall_pkg/examples
cp -r ../spall-web/examples/*     spall_pkg/examples/.
cp -r examples/*                  spall_pkg/examples/.

NOW=$(date '+%Y_%m_%d')
zip -r spall_native_$NOW.zip spall_pkg
