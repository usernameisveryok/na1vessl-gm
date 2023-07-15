client:netio server utils
	g++ client.cpp netio.o utils.o ../lib/libgmssl.a -o client.exe
server:netio utils
	g++ server.cpp netio.o utils.o ../lib/libgmssl.a -o server.exe
utils:netio
	g++ -c utils.cpp 
netio:
	g++ -c netio.cpp 
clean:
	rm *.o *.exe