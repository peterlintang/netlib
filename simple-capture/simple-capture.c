#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define MAXBYTES2CAPTURE 2048

void processPacket(u_char *arg, 
                const struct pcap_pkthdr * pkthdr,
                const u_char *packet)
{
        int i = 0;
        int *counter = NULL;
        counter = (int *)arg;

        printf("packet count: %d\n", ++(*counter));
	printf("received packet size: %d\n", pkthdr->len);
	printf("payload:\n");

	for (i = 0; i < pkthdr->len; i++) {
		if (isprint(packet[i])) 
			printf("%c", packet[i]);
		else
		printf(". ");

		if ((i%16 == 0 && i != 0) || i == pkthdr->len -1)
			printf("\n");
	}
	return ;
}


int main(int argc, char *argv[])
{
	int i = 0; 
	int count = 0;
	pcap_t *descr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device = NULL;

	memset (errbuf, 0, PCAP_ERRBUF_SIZE);

	device = pcap_lookupdev(errbuf);
	printf("opening device : %s\n", device);

	descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);

	pcap_loop(descr, -1, processPacket, (u_char *)&count);

	return 0;
}


