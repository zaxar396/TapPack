#include<iostream>
#include"pcap.h"
#pragma comment(lib,"wpcap.lib")

using namespace std; 

void another_callback(u_char *arg, const struct pcap_pkthdr* pkthdr,
	const u_char* packet)
{
	int i = 0;
	static int count = 0;

	cout << "Packet Count : " << ++count << endl;
	cout << "Recieved Packet Size: " << pkthdr->len << endl;
	cout << "Payload:" << endl;
	for (i = 0; i<pkthdr->len; i++) {
		if (isprint(packet[i]))            
		cout << packet[i] << endl;
		else
		cout << " . " << packet[i];
		if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
		cout << endl;
	}
}

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
	packet)
{
	static int count = 1;
	fprintf(stdout, "%3d, ", count);
	fflush(stdout);
	count++;
}

int main()
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	pcap_t *handle1;
	pcap_t *handle2;
	pcap_t *handle3;
	struct bpf_program filter;
	char filter_app[] = "port 80";
	char filter_app1[] = "port 52";
	char filter_app2[] = "port 53";
	char filter_app3[] = "port 54";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;

	char *devname, devs[100][100];
	int count = 1, n;
	pcap_if_t *alldevsp = nullptr, *device;
	cout << "Finding available devices ... ";
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		cout << "Error finding devices : " << errbuf;
		exit(1);
	}
	
	cout << "Done" << endl;

	cout << "Available Devices are :" << endl;
	for (device = alldevsp; device != NULL; device = device->next)
	{
		cout << count << ". " << device->name << " - " << device->description << endl;
		if (device->name != NULL)
		{
			strcpy_s(devs[count], device->name);
		}
		count++;
	}


	//dev = pcap_lookupdev(errbuf);
	//cout << dev << endl;
	handle = pcap_open_live(devs[2], BUFSIZ, 1, -1, errbuf);
	pcap_lookupnet(devs[2], &net, &mask, errbuf);
	
	

	pcap_compile(handle, &filter, filter_app, 0, net);
	pcap_setfilter(handle, &filter);
	pcap_loop(handle, -1, another_callback, NULL);

	handle1 = pcap_open_live(devs[2], BUFSIZ, 1, -1, errbuf);
	pcap_compile(handle1, &filter, filter_app1, 0, net);
	pcap_setfilter(handle1, &filter);
	pcap_loop(handle, -1, another_callback, NULL);

	handle2 = pcap_open_live(devs[2], BUFSIZ, 1, -1, errbuf);
	pcap_compile(handle2, &filter, filter_app2, 0, net);
	pcap_setfilter(handle2, &filter);
	pcap_loop(handle, -1, another_callback, NULL);

	handle3 = pcap_open_live(devs[2], BUFSIZ, 1, -1, errbuf);
	pcap_compile(handle3, &filter, filter_app3, 0, net);
	pcap_setfilter(handle3, &filter);
	pcap_loop(handle, -1, another_callback, NULL);


	//const u_char *packet;
	//packet = pcap_next(handle, &header);
	//cout << header.len << endl;

	pcap_close(handle);
	pcap_close(handle1);
	pcap_close(handle2);
	pcap_close(handle3);

	system("pause");
	return(0);
}