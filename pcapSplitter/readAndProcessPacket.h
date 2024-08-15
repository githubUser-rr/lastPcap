#ifndef READANDPROCESSPACKET_H
#define READANDPROCESSPACKET_H

#include <pcap.h>
#include <iostream>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>


class readAndProcessPacket
{
public:
    readAndProcessPacket(std::string fName);
    ~readAndProcessPacket();
    int getPacketCount() const;
    void printPackets(std::string destDirec,int packetSize);
    void parseForPacketCount(int pCount,std::string dDirec);
    void parseForPacketSize(std::string destDirec,int packetMB);
    void setDestDirec(std::string dDirec);
    void parseForTotalSize(std::string destDirec,int fileNum);


private:
    int packetCount ;
    int totalByte;

    void processPacket();

    std::string destDirec;
    std::string fileName;
    std::string pcapName;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;
    //const u_char* packet = nullptr;
    //struct pcap_pkthdr header;

    std::vector<std::vector<u_char>> packets;
    std::vector<pcap_pkthdr> headers;




    bool controlOpen;


};

#endif // READANDPROCESSPACKET_H
