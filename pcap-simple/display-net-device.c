
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv[])
{
	char *dev = NULL;
	char *net = NULL;
	char *mask = NULL;
	int	ret = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct in_addr addr;

	dev = pcap_lookupdev(errbuf);
	if (!dev) {
		fprintf(stderr, "pcap_lookupdev: %s\n", errbuf);
		exit(1);
	} else {
		fprintf(stdout, "dev name: %s\n", dev);
	}

	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if (ret < 0) {
		fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
		exit(2);
	} else {
		addr.s_addr = netp;
		net = inet_ntoa(addr);
		fprintf(stdout, "net: %s\n", net);
		addr.s_addr = maskp;
		mask = inet_ntoa(addr);
		fprintf(stdout, "mask: %s\n", mask);
	}
	return 0;
}
