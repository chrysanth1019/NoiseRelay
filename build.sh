sudo cp main.c ./noise-c/examples/echo/echo-server/echo-server.c
cd noise-c
sudo ./autogen.sh
sudo ./configure
sudo make
cd ..
sudo mv ./noise-c/examples/echo/echo-server/echo-server noise-relay