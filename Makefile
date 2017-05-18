packetspammer: packetspammer.c
	 ${CC} -Wall radiotap.c packetspammer.c -o packetspammer -lpcap

clean:
	rm -f packetspammer *~

send:	packetspammer
	scp packetspammer root@10.0.1.193:/media/realroot/
	scp packetspammer root@10.0.1.192:/media/realroot/

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp packetspammer $(DESTDIR)/usr/bin

style:
	cstyle packetspammer.c radiotap.c
