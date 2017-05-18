all: packetspammer ainject

packetspammer: packetspammer.c
	 ${CC} -Wall radiotap.c packetspammer.c -o packetspammer -lpcap

ainject: inject.c
	 ${CC} -Wall radiotap.c inject.c -o inject -lpcap

clean:
	rm -f packetspammer *~
	rm -f inject 

send: 
	scp packetspammer inject root@10.0.1.193:/media/realroot/
	scp packetspammer inject root@10.0.1.192:/media/realroot/

#install:
#	mkdir -p $(DESTDIR)/usr/bin
#	cp packetspammer $(DESTDIR)/usr/bin
	

style:
	cstyle packetspammer.c radiotap.c inject.c
