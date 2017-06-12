#include <stdio.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Defined in include/linux/ieee80211.h */
struct ieee80211_hdr {
	uint16_t /*__le16*/frame_control;
	uint16_t /*__le16*/duration_id;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t /*__le16*/seq_ctrl;
//uint8_t addr4[6];
}__attribute__ ((packed));

static const uint8_t u8aRadiotapHeader[] = {

0x00, 0x00, // <-- radiotap version (ignore this)
		0x18, 0x00, // <-- number of bytes in our header (count the number of "0x"s)

		/**
		 * The next field is a bitmap of which options we are including.
		 * The full list of which field is which option is in ieee80211_radiotap.h,
		 * but I've chosen to include:
		 *   0x00 0x01: timestamp
		 *   0x00 0x02: flags
		 *   0x00 0x03: rate
		 *   0x00 0x04: channel
		 *   0x80 0x00: tx flags (seems silly to have this AND flags, but oh well)
		 */
		0x0f, 0x80, 0x00, 0x00,

		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp

		/**
		 * This is the first set of flags, and we've set the bit corresponding to
		 * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the end
		 * of our buffer for us.
		 */
		0x10,

		0x00, // <-- rate
		0x00, 0x00, 0x00, 0x00, // <-- channel

		/**
		 * This is the second set of flags, specifically related to transmissions. The
		 * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
		 * wait for an ACK for this frame, and that it won't retry if it doesn't get
		 * one.
		 */
		0x08, 0x00, };

/**
 * After an 802.11 MAC-layer header, a logical link control (LLC) header should
 * be placed to tell the receiver what kind of data will follow (see IEEE 802.2
 * for more information).
 *
 * For political reasons, IP wasn't allocated a global so-called SAP number,
 * which means that a simple LLC header is not enough to indicate that an IP
 * frame was sent. 802.2 does, however, allow EtherType types (the same kind of
 * type numbers used in, you guessed it, Ethernet) through the use of the
 * "Subnetwork Access Protocol", or SNAP. To use SNAP, the three bytes in the
 * LLC have to be set to the magical numbers 0xAA 0xAA 0x03. The next five bytes
 * are then interpreted as a SNAP header. To specify an EtherType, we need to
 * set the first three of them to 0. The last two bytes can then finally be set
 * to 0x0800, which is the IP EtherType.
 */
const uint8_t ipllc[8] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00 };


void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet);
void pktdump(const u_char * pu8, int nLength);

//int nDelay = 100000;
#define BILLION  1000000000L
char command1[50];
char command2[50];
char command3[50];
char command4[50];
char command5[50];

//int main(int argc, char **argv) {
int main() {
	strcpy(command1, "echo -n \"40\" > /sys/class/gpio/unexport");
	strcpy(command2, "echo -n \"40\" > /sys/class/gpio/export");
	strcpy(command3, "echo -n \"out\" > /sys/class/gpio/gpio40/direction");
	strcpy(command4, "echo -n \"1\" > /sys/class/gpio/gpio40/value");
	strcpy(command5, "echo -n \"0\" > /sys/class/gpio/gpio40/value");
	system(command1);
	system(command2);
	system(command3);

	//
	struct timespec start_time;
	struct timespec end_time;
	long int diffInNanos;
	long int diffSec;
	uint8_t packno = 1;
	uint8_t max_packno = 20;
//	char buff[100];

/*	 The parts of our packet
	uint8_t *rt;  radiotap
	struct ieee80211_hdr *hdr;
	uint8_t *llc;
	struct iphdr *iph;
	struct udphdr *udp;
	uint8_t *data;
	struct timespec *ntime;
	uint8_t *stime;

	 Other useful bits
	uint8_t *buf;
	size_t sz;*/

	// pkt vars
	char dev[] = "mon0";
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr packet_header;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_exp[] =
			"udp && src 169.254.1.1 && dst 255.255.255.255 && src port 50505 && dst port 50505";
	bpf_u_int32 subnet_mask, ip;
	int pktlength = 0;

	if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
		printf("Could not get information for device: %s\n", dev);
		ip = 0;
		subnet_mask = 0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 0, error_buffer);
	if (handle == NULL) {
		printf("Could not open %s - %s\n", dev, error_buffer);
		return 2;
	}
	if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
		printf("Bad filter - %s\n", pcap_geterr(handle));
		return 2;
	}
	if (pcap_setfilter(handle, &filter) == -1) {
		printf("Error setting filter - %s\n", pcap_geterr(handle));
		return 2;
	}

	char timestr[50];
	long int rtime;
	FILE *fp;
	char *ptr;
	char *cmd = "ssh root@10.0.1.193 date +%s%N";
	errno = 0;

	printf("\n Let get the time sync diff \n");

	memset(&timestr[0], 0, sizeof(timestr));

	if ((fp = popen(cmd, "r")) == NULL) {
		printf("Error opening pipe!\n");
		return -1;
	}

	while (fgets(timestr, 50, fp) != NULL) {
		// Do whatever you want here...
		printf("OUTPUT: %s", timestr);
		rtime = strtoll(timestr, &ptr, 10);
		if(*ptr != 0 ) {
			printf("There is ptr error %s", ptr);
		}
		else if ( errno != 0) {
			printf("There is a error error no %d",errno );
		} else {
			printf("The rtime is : %ld",rtime);
		}
	}

	if (pclose(fp)) {
		printf("Command not found or exited with error status\n");
		return -1;
	}

	printf("\nLets start ....\n");
	system(command4);
	sleep(5);
	system(command5);

	while (1) {

		// pcap_next() or pcap_loop() to get packets from device now
		// Only packets over port 80 will be returned.
		clock_gettime(CLOCK_REALTIME, &start_time);
		//printf("Waiting for packet %ld.%ld \n",start_time.tv_sec, start_time.tv_nsec);
		packet = pcap_next(handle, &packet_header);
		if (packet == NULL) {
			printf("No packet found.\n");
		} else {
			clock_gettime(CLOCK_REALTIME, &end_time);

			if (end_time.tv_nsec >= start_time.tv_nsec
					&& end_time.tv_sec >= start_time.tv_sec) {
				diffSec = (end_time.tv_sec - start_time.tv_sec);
				diffInNanos = (end_time.tv_nsec - start_time.tv_nsec);

			} else if (start_time.tv_nsec > end_time.tv_nsec
					&& end_time.tv_sec >= start_time.tv_sec) {
				diffSec = (end_time.tv_sec - start_time.tv_sec);
				diffInNanos =
						((BILLION - start_time.tv_nsec) + end_time.tv_nsec);

			} else {
				// 1 sec ... somthing wrong
				diffSec = 1;
				diffInNanos = 0;
			}

/*			 Total buffer size (note the 0 bytes of data and the 4 bytes of FCS
			sz = sizeof(u8aRadiotapHeader) + sizeof(struct ieee80211_hdr)
					+ sizeof(ipllc) + sizeof(struct iphdr)
					+ sizeof(struct udphdr) + 0sizeof(uint8_t)
					+ sizeof(struct timespec) + 100  data + 4  FCS ;

			// String time bufer
			buf = (uint8_t *) malloc(sz);

			// let copy the packet
			 memcpy(buf, packet, sz);

			 Put our pointers in the right place
			rt = (uint8_t *) buf;
			hdr = (struct ieee80211_hdr *) (rt + sizeof(u8aRadiotapHeader));
			llc = (uint8_t *) (hdr + 1);
			iph = (struct iphdr *) (llc + sizeof(ipllc));
			udp = (struct udphdr *) (iph + 1);
			// packet number
			data = (uint8_t *) (udp + 1);
			// Epoch time
			ntime = (struct timespec *) (data + 1);
			// Date and Time in string
			stime = (uint8_t *) (ntime + 1);*/

			//strftime(buff, sizeof buff, "%D %T", gmtime(&end_time.tv_sec));
			//printf("Got a packet [%d] at %s.%09ld with %ld ns \n\n",packno, buff,end_time.tv_nsec, diffInNanos);
			printf("Got a packet [%d] at %ld sec %ld nano sec "
					"(with %ld.%ld nano sec) \n", packno, end_time.tv_sec,
					end_time.tv_nsec, diffSec, diffInNanos);
			//system(command4);
			//system(command5);

			pktlength = packet_header.len;
			printf("Lenght  of packet %d\n", pktlength);
			pktdump(packet, pktlength);
			//print_packet_info(packet, packet_header);
			//free(buf);
			if (packno >= max_packno) {
				sleep(5);
				printf("\n Let finish ....\n");
				pcap_close(handle);
				return 0;
			}
			packno++;
		}
	}

	/*
	 int snapshot_length = 1024;
	 int total_packet_count = 200;
	 u_char *my_arguments = NULL;
	 pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);
	 */
	sleep(5);
	printf("\n Let finish ....\n");
	pcap_close(handle);

	return 0;
}

void pktdump(const u_char * pu8, int nLength) {
	char sz[256], szBuf[512], szChar[17], *buf; //, fFirst = 1;
	unsigned char baaLast[2][16];
	unsigned int n, nPos = 0, nStart = 0, nLine = 0; //, nSameCount = 0;

	buf = szBuf;
	szChar[0] = '\0';

	for (n = 0; n < nLength; n++) {
		baaLast[(nLine & 1) ^ 1][n & 0xf] = pu8[n];
		if ((pu8[n] < 32) || (pu8[n] >= 0x7f))
			szChar[n & 0xf] = '.';
		else
			szChar[n & 0xf] = pu8[n];
		szChar[(n & 0xf) + 1] = '\0';
		nPos += sprintf(&sz[nPos], "%02X ", baaLast[(nLine & 1) ^ 1][n & 0xf]);
		if ((n & 15) != 15)
			continue;
		//        if ((memcmp(baaLast[0], baaLast[1], 16) == 0) && (!fFirst)) {
		//                nSameCount++;
		//        } else {
		//                if (nSameCount)
		//                        buf += sprintf(buf, "(repeated %d times)\n",
		//                                nSameCount);
		buf += sprintf(buf, "%04x: %s %s\n", nStart, sz, szChar);
		//nSameCount = 0;
		printf("%s", szBuf);
		buf = szBuf;
		//        }
		nPos = 0;
		nStart = n + 1;
		nLine++;
		//fFirst = 0;
		sz[0] = '\0';
		szChar[0] = '\0';
	}
	//if (nSameCount)
	//        buf += sprintf(buf, "(repeated %d times)\n", nSameCount);

	buf += sprintf(buf, "%04x: %s", nStart, sz);
	if (n & 0xf) {
		*buf++ = ' ';
		while (n & 0xf) {
			buf += sprintf(buf, "   ");
			n++;
		}
	}
	buf += sprintf(buf, "%s\n", szChar);
	printf("%s", szBuf);
}

/*

 void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
 u_char *pointer;
 int address_length;

 printf(
 "Time recieved: %s\n",
 ctime((const time_t*)&packet_header.ts.tv_sec)
 );
 printf("Packet length %d\n", packet_header.len);
 printf("Packet capture length: %d\n", packet_header.caplen);

 // What type of ethernet packet
 struct ether_header *ethernet_header;
 ethernet_header = (struct ether_header *) packet;
 if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
 printf(
 "Ethernet type hex:%x dec:%d is an IP packet.\n",
 ntohs(ethernet_header->ether_type),
 ntohs(ethernet_header->ether_type)
 );
 } else  if (ntohs (ethernet_header->ether_type) == ETHERTYPE_ARP) {
 printf(
 "Ethernet type hex:%x dec:%d is an ARP packet.\n",
 ntohs(ethernet_header->ether_type),
 ntohs(ethernet_header->ether_type)
 );
 } else {
 printf("Other ethernet type: %x", ntohs(ethernet_header->ether_type));
 return;
 }

 // Source address
 address_length = ETHER_ADDR_LEN;
 pointer = ethernet_header->ether_shost;
 printf("Source Address:  ");
 do {
 printf(
 "%s%x",
 (address_length == ETHER_ADDR_LEN) ? " " : ":", *pointer++
 );
 } while(--address_length > 0);
 printf("\n");

 // Destination address
 pointer = ethernet_header->ether_dhost;
 address_length = ETHER_ADDR_LEN;
 printf("Destination Address:  ");
 do {
 printf(
 "%s%x",
 (address_length == ETHER_ADDR_LEN) ? " " : ":", *pointer++
 );
 } while(--address_length > 0);
 printf("\n");
 }

 */

/*

 void my_packet_handler(
 u_char *args,
 const struct pcap_pkthdr *header,
 const u_char *packet
 )
 {

 //int nDelay = 10;
 char command4[50];
 char command5[50];

 strcpy(command4, "echo -n \"1\" > /sys/class/gpio/gpio40/value");
 strcpy(command5, "echo -n \"0\" > /sys/class/gpio/gpio40/value");

 system(command4);
 //usleep(nDelay);
 system(command5);



 }
 */

/* Finds the payload of a TCP/IP packet */
/*
 void my_packet_handler(
 u_char *args,
 const struct pcap_pkthdr *header,
 const u_char *packet
 )
 {
 // First, lets make sure we have an IP packet
 struct ether_header *eth_header;
 eth_header = (struct ether_header *) packet;
 if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
 printf("Not an IP packet. Skipping...\n\n");
 return;
 }

 // The total packet length, including all headers
 //   and the data payload is stored in
 //   header->len and header->caplen. Caplen is
 //   the amount actually available, and len is the
 //   total packet length even if it is larger
 //   than what we currently have captured. If the snapshot
 //  length set with pcap_open_live() is too small, you may
 //  not have the whole packet.
 printf("Total packet available: %d bytes\n", header->caplen);
 printf("Expected packet size: %d bytes\n", header->len);

 // Pointers to start point of various headers
 const u_char *ip_header;
 const u_char *tcp_header;
 const u_char *payload;

 // Header lengths in bytes
 int ethernet_header_length = 14; // Doesn't change
 int ip_header_length;
 int tcp_header_length;
 int payload_length;

 // Find start of IP header
 ip_header = packet + ethernet_header_length;
 // The second-half of the first byte in ip_header
 //   contains the IP header length (IHL).
 ip_header_length = ((*ip_header) & 0x0F);
 // The IHL is number of 32-bit segments. Multiply
 //   by four to get a byte count for pointer arithmetic
 ip_header_length = ip_header_length * 4;
 printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

 // Now that we know where the IP header is, we can
 //   inspect the IP header for a protocol number to
 //  make sure it is TCP before going any further.
 //   Protocol is always the 10th byte of the IP header
 u_char protocol = *(ip_header + 9);
 if (protocol != IPPROTO_TCP) {
 printf("Not a TCP packet. Skipping...\n\n");
 return;
 }

 // Add the ethernet and ip header length to the start of the packet
 //   to find the beginning of the TCP header
 tcp_header = packet + ethernet_header_length + ip_header_length;
 // TCP header length is stored in the first half
 //   of the 12th byte in the TCP header. Because we only want
 //   the value of the top half of the byte, we have to shift it
 //   down to the bottom half otherwise it is using the most
 //   significant bits instead of the least significant bits
 tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
 // The TCP header length stored in those 4 bits represents
 //   how many 32-bit words there are in the header, just like
 //   the IP header length. We multiply by four again to get a
 //   byte count.
 tcp_header_length = tcp_header_length * 4;
 printf("TCP header length in bytes: %d\n", tcp_header_length);

 // Add up all the header sizes to find the payload offset
 int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
 printf("Size of all headers combined: %d bytes\n", total_headers_size);
 payload_length = header->caplen -
 (ethernet_header_length + ip_header_length + tcp_header_length);
 printf("Payload size: %d bytes\n", payload_length);
 payload = packet + total_headers_size;
 printf("Memory address where payload begins: %p\n\n", payload);

 // Print payload in ASCII
 if (payload_length > 0) {
 const u_char *temp_pointer = payload;
 int byte_count = 0;
 while (byte_count++ < payload_length) {
 printf("%c", *temp_pointer);
 temp_pointer++;
 }
 printf("\n");
 }

 return;
 }
 */
