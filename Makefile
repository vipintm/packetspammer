packetspammer: packetspammer.c
	 ${CC} -Wall radiotap.c packetspammer.c -o packetspammer -lpcap

clean:
	rm -f packetspammer *~

send:	packetspammer
	scp packetspammer root@10.0.1.193:/usr/local/bin
	scp packetspammer root@10.0.1.192:/usr/local/bin

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp packetspammer $(DESTDIR)/usr/bin

style:
	cstyle packetspammer.c radiotap.c
