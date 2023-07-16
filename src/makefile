OUTPWD = ../bin/
all:client server gencert
client:netio message
	g++ client.cpp netio.o message.o ../lib/libgmssl.a -o ../bin/client.exe
server:netio message
	g++ server.cpp netio.o message.o ../lib/libgmssl.a -o ../bin/server.exe
message:netio
	g++ -c message.cpp 
gencert:
	g++ gencert.cpp ../lib/libgmssl.a -o ../bin/gencert.exe
netio:
	g++ -c netio.cpp 
clean:
	rm *.o *.exe