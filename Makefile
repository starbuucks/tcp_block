all: tcp_block

tcp_block: main.o packet.o http_util.o packet_util.o block.o
	g++ -g -o tcp_block main.o block.o packet_util.o http_util.o packet.o -lpcap

block.o: block.cpp block.h packet.h
	g++ -g -c -o block.o block.cpp

packet_util.o: packet_util.cpp packet_util.h packet.h
	g++ -g -c -o packet_util.o packet_util.cpp

http_util: http_util.cpp http_util.h
	g++ -g -c -o http_util.o http_util.cpp

packet: packet.cpp packet.h
	g++ -g -c -o packet.o packet.cpp

clean:
	rm -f tcp_block
	rm -f *.o


