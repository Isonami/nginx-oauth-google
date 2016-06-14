#!/bin/sh
env ASSUME_ALWAYS_YES=YES pkg install lua51 gmake curl lua51-cjson
mkdir -p /tmp/installlua
cd /tmp/installlua
luarocks=`curl http://keplerproject.github.io/luarocks/releases/ 2>/dev/null | grep -m 1 -E "luarocks-([0-9]+\.)+tar\.gz" | awk -F'"' '{print $2}'`
fetch "http://keplerproject.github.io/luarocks/releases/$luarocks"
tar -xf $luarocks
lurdir=`echo $luarocks | awk -F'\.tar\.gz' '{print $1}'`
cd $lurdir
./configure --with-lua-include=/usr/local/include/lua51 --with-downloader=curl --lua-version=5.1
make build && make install
make bootstrap
luarocks install lua-resty-session
luarocks install lua-resty-string
fetch https://raw.githubusercontent.com/openresty/lua-resty-lock/master/lib/resty/lock.lua -o /usr/local/share/lua/5.1/resty/lock.lua
cd -
rm -r /tmp/installlua
