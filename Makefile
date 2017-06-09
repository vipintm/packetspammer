all: packetspammer ainject packetvector packet-generator packet_parser using_filters packet-generator-fastgpio

packet-generator-fastgpio : packet-generator-fastgpio.c
	${CC} packet-generator-fastgpio.c -o packet-generator-fastgpio -lpcap

using_filters: using_filters.c
	${CC} -Wall using_filters.c -o using_filters -lpcap

packet_parser: packet_parser.c
	${CC} packet_parser.c -o packet_parser -lpcap

packet-generator: packet-generator.c 
	${CC} -Wall packet-generator.c -o packet-generator -lpcap

packetspammer: packetspammer.c
	 ${CC} radiotap.c packetspammer.c -o packetspammer -lpcap

ainject: inject.c
	 ${CC} radiotap.c inject.c -o inject -lpcap

packetvector: packetvector.c vectors.h
	 ${CC} radiotap.c packetvector.c -o packetvector -lpcap

clean:
	rm -f packetspammer *~
	rm -f inject 
	rm -f packetvector
	rm -f packet-generator
	rm -f packet_parser
	rm -f using_filters
	rm -f packet-generator-fastgpio

send: 
	scp packetspammer inject packetvector packet-generator packet_parser using_filters packet-generator-fastgpio root@10.0.1.193:/media/realroot/
	scp packetspammer inject packetvector packet-generator packet_parser using_filters packet-generator-fastgpio root@10.0.1.192:/media/realroot/

#install:
#	mkdir -p $(DESTDIR)/usr/bin
#	cp packetspammer $(DESTDIR)/usr/bin
	

style:
	cstyle packetspammer.c radiotap.c inject.c
