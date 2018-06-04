#include <string>
#include <iostream>
#include <pcap.h>


using namespace std;

int main(int argc, char *argv[])
{

	int num, inum, i = 0;
	pcap_if_t *alldevs = 0;		//network devices		
	pcap_t *adhandle;		//session handle
	struct bpf_program fcode;
	bpf_u_int32 net;		//the IP of our filtering device
	bpf_u_int32 mask;		//the netmask of filtering device
	char *dev;

	//input a file name to open
	//string file = "D:\\Documents\\Classes\\Graduate\\EEL6935 - Cyber Security\\Project\\FinalProject.pcap";
	string file = "D:\\Documents\\Classes\\Graduate\\EEL6935 - Cyber Security\\Project\\PCAP\\ProjectFiles\\ProjectFile_00008_20131201235204.pcap";

	//errbuf in pcacp_open functions is assumed to be able to hold at least PCAP_ERRBUF chars, which is defined as 256
	char errbuff[PCAP_ERRBUF_SIZE];

	//use pcap_open_offline to open the file
	pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);

	//create a heather object
	struct pcap_pkthdr *header;

	//create a character array using a u_char
	const u_char *data;

	dev = pcap_lookupdev(errbuff);

	if (pcap_lookupnet(dev, &net, &mask, errbuff) == -1)
	{
		fprintf(stderr, "Cant get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	//loop through the packet
	u_int packetCount = 0;
	while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
	{
		//compiles the filter
		//the const char * position is where the filter is put in place
		if (pcap_compile(pcap, &fcode, "port 53", 1, net) < 0)
		{
			fprintf(stderr, "\nThe program is unable to compile the packet filter, ERROR \n");
			//frees the device list
			pcap_freealldevs(alldevs);
			return -1;
		}

		//SETS FILTER
		if (pcap_setfilter(pcap, &fcode) < 0)
		{
			fprintf(stderr, "\nThere is an error setting the filter ERROR 2 \n");
			pcap_freealldevs(alldevs);
			return -1;
		}

		//using printf allows the program to print out the following:
		//shows the packtet number
		//printf("Packet # %i\n", ++packetCount);

		//shows the size in bytes of the packet
		//printf("packet size: %d Bytes\n", header->len);

		//Shows a warning if the length captures id different
		//if (header->len != header->caplen)
		//	printf("WARNING !!! Capture size different than packet size: $ld bytes\n", header->len);

		//Shows Epoch time
		//printf("Epoch time: %d:%d seconds\n", header->ts.tv_usec);

		//This adds two lines between packets
		//printf("\n\n");
		packetCount = packetCount + 1;
	}
	printf("Packet # %i\n", packetCount);

	cin >> num;
	printf("done");
}
