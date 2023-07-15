all:client server gencert
client:netio utils
	g++ client.cpp netio.o utils.o ../lib/libgmssl.a -o client.exe
server:netio utils
	g++ server.cpp netio.o utils.o ../lib/libgmssl.a -o server.exe
utils:netio
	g++ -c utils.cpp 
gencert:
	g++ gencert.cpp ../lib/libgmssl.a -o gencert.exe
netio:
	g++ -c netio.cpp 
clean:
	rm *.o *.exe