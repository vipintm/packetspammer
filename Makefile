all: packetspammer ainject packetvector packet-generator

packet-generator: packet-generator.c 
	${CC} -Wall packet-generator.c -o packet-generator -lpcap

packetspammer: packetspammer.c
	 ${CC} -Wall radiotap.c packetspammer.c -o packetspammer -lpcap

ainject: inject.c
	 ${CC} -Wall radiotap.c inject.c -o inject -lpcap

packetvector: packetvector.c vectors.h
	 ${CC} -Wall radiotap.c packetvector.c -o packetvector -lpcap

clean:
	rm -f packetspammer *~
	rm -f inject 
	rm -f packetvector
	rm -f packet-generator

send: 
	scp packetspammer inject packetvector packet-generator root@10.0.1.193:/media/realroot/
	scp packetspammer inject packetvector packet-generator root@10.0.1.192:/media/realroot/

#install:
#	mkdir -p $(DESTDIR)/usr/bin
#	cp packetspammer $(DESTDIR)/usr/bin
	

style:
	cstyle packetspammer.c radiotap.c inject.c
