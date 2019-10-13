#include<iostream>
#include<pcap.h>
#include<string>
#include<fstream>
#include<vector>
#include<algorithm>
#include<ctime>
#include<conio.h>
#include<Windows.h>
#include<chrono>
#include<stdio.h>
#include<time.h>



using namespace std;

/* 4 bytes IP address */
typedef struct ip_address {
	u_char byte1 = '0';
	u_char byte2 = '0';
	u_char byte3 = '0';
	u_char byte4 = '0';
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header */
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

// get the port from the packet
u_short getPort(u_short const net) {
	uint8_t data[2] = {};
	memcpy(&data, &net, sizeof(data));
	return ((u_short)data[1] << 0)
		| ((u_short)data[0] << 8);
}

typedef struct verEntry {
	ip_address  target;      // Destination address
	vector<u_short> ports;      // Port
	u_short packetCount = 0;
	time_t      startTime;
	time_t      endTime;
	int       rate = 0;
} verEntry;

typedef struct horEntry {
	u_short port;  // Destination address
	vector<ip_address> targets;      // Port
	u_short packetCount = 0;
	time_t      startTime;
	time_t      endTime;
	int       rate = 0;
} horEntry;

typedef struct entry {
	ip_address  target;      // Destination address
	u_short     port;      // Port
	time_t      time;
} entry;



void verticalScanCheck(entry e);
void horizontalScanCheck(entry e);
void timeConvertion(time_t etime, ofstream& os);
verEntry newEvent_VS(entry e);
horEntry newEvent_HS(entry e);
void display_IPaddr(ip_address ip, ofstream& os);

vector<verEntry> verScan;
vector<u_short>::iterator vit;
vector<horEntry> horScan;
vector<ip_address>::iterator hit;

int main(int argc, char *argv[])
{
	system("color 0e");
	system("color 0A");
	char a = 0, b = 219;
	cout << "\t\t EEL 6935- Cyber Security: Measurement and Data Analysis\n\n";
	cout << "\t Loading PCAP file:  ";
	for (int i = 0; i <= 20; i++)
		cout << a;
	Sleep(100);
	cout << "\r";
	cout << "\t\t\t\t\t";
	for (int i = 0; i <= 20; i++)
	{
		cout << b;
		Sleep(50);
	}

	
	int inum, i = 0;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char *dev;
	ip_header *ih;
	u_int ip_len;

    
	// string file = "D:\\Documents\\Classes\\Graduate\\EEL6935 - Cyber Security\\Project\\PCAP\\ProjectFiles\\ProjectFile_00008_20131201235204.pcap";
	 //string file = "D:\\Documents\\Classes\\Graduate\\EEL6935 - Cyber Security\\Project\\PCAP\\test files\\6-10.pcap"; 
	 string file = "D:\\Documents\\Classes\\Graduate\\EEL6935 - Cyber Security\\Project\\PCAP\\S-Files\\ProjectFile_00008_20131201235204.pcap";

	char errbuff[PCAP_ERRBUF_SIZE];

	pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);

	struct pcap_pkthdr *header;

	const u_char *data;
	dev = pcap_lookupdev(errbuff);
	
	if (pcap_lookupnet(dev, &net, &mask, errbuff) == -1)
	{
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	u_int packetCount = 0;
	int count = 0;
	cout << "Parsing pcap...\n";
 	clock_t t;
	t = clock();
	// cout.flush();

	while (packet = pcap_next(handle, &header)) {

		packet_counter++;

	}
	pcap_close(handle);


	printf("%d\n", packet_counter);
	return 0;
}
	
	while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0 )
	{
		
		ih = (ip_header *)(data +14);
		
		ip_len = (ih->ver_ihl & 0xf) * 4;
		udp_header *uh;
		u_int ip_len;
		ip_len = (ih->ver_ihl & 0xf) * 4;
		uh = (udp_header *)((u_char*)ih + ip_len);

		entry e;
		u_short sport, dport;
		sport = getPort(uh->sport);
		dport = getPort(uh->dport);
		
		e.target.byte1 = ih->saddr.byte1;
		e.target.byte2 = ih->saddr.byte2;
		e.target.byte3 = ih->saddr.byte3;
		e.target.byte4 = ih->saddr.byte4;
		e.port = dport;
		e.time = header->ts.tv_sec;
		horizontalScanCheck(e);
		verticalScanCheck(e);
		
	}

	   ofstream output("D:\\Documents\\Classes\\Graduate\\EEL6935 - Cyber Security\\Project\\PCAP\\ProjectFiles\\Data_02.txt");
	
	    int entryCounter = 0;
	    cout << "\n\n All packets have been analyzed completed\n";
		output << "\n ************* Cyber Analysis Report *****************\n\n ";
		
		output << "\n Number of possible vertical probing/scanning: " << verScan.size() << "\n";
		output << "--------------------------------------------------------------------------\n";
		for (int i = 0; i < verScan.size(); ++i)
		{
			output << "Entry # " << ++entryCounter << '\n';
			output << "Start date/time: ";
			timeConvertion(verScan[i].startTime, output);
			output << "End date/time:   ";
			timeConvertion(verScan[i].endTime, output);
			display_IPaddr(verScan[i].target, output);
			output << " has scanned for " << (u_short)verScan[i].ports.size() << " ports\n";
			output << "Ports: ";
			for (vit = verScan[i].ports.begin(); vit != verScan[i].ports.end(); ++vit)
				output << *vit << " ";
			output << "\nNumber of packets: " << verScan[i].packetCount << '\n';
			int t = int(verScan[i].endTime - verScan[i].startTime);
			if (t <= 0)
				output << "Packet rate: N/A\n";
			else
				output << "Packet rate: " << double(verScan[i].packetCount)/double(t) << " packets per second\n";
			output << "\n\n";
		}
		
		output << "--------------------------------------------------------------------------\n";
		output << "\n Number of possible horizontal probing/scanning: " << horScan.size() << "\n";
		output << "--------------------------------------------------------------------------\n";
	    entryCounter = 0;
		for (int i = 0; i < horScan.size(); ++i)
		{
			output << "Entry # " << ++entryCounter << '\n';
			output << "Start date/time: ";
			timeConvertion(horScan[i].startTime, output);
			output << "End date/time:   ";
			timeConvertion(horScan[i].endTime, output);
			output << "Port: " << horScan[i].port << " has scanned from the following " 
				   << horScan[i].targets.size() << " hosts:\n";
			output << "IPs: ";
			for (int j = 0; j < horScan[i].targets.size(); ++j)
				display_IPaddr(horScan[i].targets[j], output);
			output << "\nNumber of packets: " << horScan[i].packetCount << '\n';
			int t = int(horScan[i].endTime - horScan[i].startTime);
			if (t <= 0)
				output << "Packet rate: N/A\n";
			else
		    	output << "Packet rate: " << double(horScan[i].packetCount)/double(t) << " packets per second\n";
			output << "\n\n";

		}
		output << "--------------------------------------------------------------------------\n";
		output.close();
		t = clock() - t;
		cout << "time: " << t * 1.0 / CLOCKS_PER_SEC << " seconds" << endl;

		//cout << "\nPlease Open report for analysis\n";
	system("pause");
	return 0;
}

void horizontalScanCheck(entry e)
{
	cout << (u_short)e.target.byte1 << "."
		<< (u_short)e.target.byte2 << "."
		<< (u_short)e.target.byte3 << "."
		<< (u_short)e.target.byte4 << '\n';
	if (horScan.empty()) // first event
		horScan.push_back(newEvent_HS(e));
	else
	{
		bool found = false;
		int index = -1;
		// check if a new port
		for (int i = 0; i < horScan.size(); ++i)
		{
			if (horScan[i].port == e.port)
			{
				index = i;
				horScan[index].packetCount++;
				break;
			}	    
		}
		if (index >= 0 ) // no new event. Port has already been detected. 
		{
            // check if IP address is new.
			for (int i = 0; i < horScan[index].targets.size(); ++i) 
			{
				if (horScan[index].targets[i].byte1 == e.target.byte1 && horScan[index].targets[i].byte2 == e.target.byte2 &&
					horScan[index].targets[i].byte3 == e.target.byte3 && horScan[index].targets[i].byte4 == e.target.byte4)
				{
					found = true;
					break;
				}
				
			}
			if (!found) // new IP address to be added it event.
			{
				ip_address ip;
				ip.byte1 = e.target.byte1;
				ip.byte2 = e.target.byte2;
				ip.byte3 = e.target.byte3;
				ip.byte4 = e.target.byte4;
				horScan[index].targets.push_back(ip);
			}
			// update end time of event
			horScan[index].endTime = e.time;
			// ignore IP address
		}
		else // new event
			horScan.push_back(newEvent_HS(e));
		
	}
}

horEntry newEvent_HS(entry e)
{
	horEntry h;
	ip_address ip;
	h.port = e.port;
	ip.byte1 = e.target.byte1;
	ip.byte2 = e.target.byte2;
	ip.byte3 = e.target.byte3;
	ip.byte4 = e.target.byte4;
	h.targets.push_back(ip);
	h.startTime = e.time;
	h.endTime = e.time;
	h.packetCount++;
	return h;
}
void verticalScanCheck(entry e)
{
	if (verScan.empty()) // first event
		verScan.push_back(newEvent_VS(e));
	else
	{
		bool found = false;
		// check if new IP address
		for (int i = 0; i < verScan.size(); ++i)
		{
			if (verScan[i].target.byte1 == e.target.byte1 && verScan[i].target.byte2 == e.target.byte2 &&
				verScan[i].target.byte3 == e.target.byte3 && verScan[i].target.byte4 == e.target.byte4)
			{
				verScan[i].packetCount++;
				if (verScan[i].ports.empty())
				      verScan[i].ports.push_back(e.port);
				else 
					{
						vit = find(verScan[i].ports.begin(), verScan[i].ports.end(), e.port);
						  if ( vit == verScan[i].ports.end())
							  verScan[i].ports.push_back(e.port);
					}
				verScan[i].endTime = e.time;
				found = true;
				break;
			}
		}
		if (!found) // IP not found. create new event
			verScan.push_back(newEvent_VS(e));
		
	}
}

verEntry newEvent_VS(entry e)
{
	verEntry v;
	v.target.byte1 = e.target.byte1;
	v.target.byte2 = e.target.byte2;
	v.target.byte3 = e.target.byte3;
	v.target.byte4 = e.target.byte4;
	v.ports.push_back(e.port);
	v.startTime = e.time;
	v.endTime = e.time;
	v.packetCount++;
	return v;

}

void display_IPaddr(ip_address ip, ofstream& os)
{
	os << (u_short)ip.byte1 << "."
		<< (u_short)ip.byte2 << "."
		<< (u_short)ip.byte3 << "."
		<< (u_short)ip.byte4;
}

void timeConvertion(time_t eTime, ofstream& os)
{
	char realTime[32];
	struct tm *ltime = localtime(&eTime);
	strftime(realTime, sizeof realTime, "\Date %F. Time %H:%M:%S", ltime);
	realTime[31] = '\0';
	os << realTime << '\n';
}
