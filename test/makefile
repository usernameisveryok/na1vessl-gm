test_netio_receive:test_netio_send
	g++ test_netio_receive.cpp netio.o  -o test_netio_receive.exe
test_netio_send:netio
	g++ test_netio_send.cpp netio.o  -o test_netio_send.exe
netio:
	g++ -c ../src/netio.cpp -o netio.o
clean:
	rm *.o *.exe