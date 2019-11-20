all: tcp_block

tcp_block: main.o packet.o http_util.o packet_util.o tcp_block.o
	g++ -g -o tcp_block main.o tcp_block.o packet_util.o http_util.o packet.o -lpcap

tcp_block.o: tcp_block.cpp tcp_block.h packet.h packet_util.h
	g++ -g -c -o tcp_block.o tcp_block.cpp

packet_util.o: packet_util.cpp packet_util.h packet.h
	g++ -g -c -o packet_util.o packet_util.cpp

http_util: http_util.cpp http_util.h
	g++ -g -c -o http_util.o http_util.cpp

packet: packet.cpp packet.h
	g++ -g -c -o packet.o packet.cpp

clean:
	rm -f tcp_block
	rm -f *.o


