#include "packetoperation.h"
#include "MoveWorker.h"
#include "workerUpdate.h"


#include <typeinfo> // veri türlerini kontrol etmek için kullandım şuan kullanılmıyor
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <cstdlib>
#include <fstream>
#include <unordered_map>
#include <chrono>
#include <cerrno> // bu ikisi hata kodu için
#include <cstring>
#include <filesystem>
#include <QThread>
#include <vector>
#include <QString>
#include <QObject>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>

#include <pthread.h>


#define ETHERNET_HEADER_LENGTH 14
/*#define defaultPath "C:/Users/remzi/Desktop/sessionOut/"
#define defaultTshark "C:/Users/remzi/Desktop/tsharkOutput/"

string defaultPath = "C:\\Users\\remzi\\Desktop\\sessionOut\\";
string defaultTshark = "C:/Users/remzi/Desktop/tsharkOutput/";
string defaultTxtPath = "C:\\Users\\remzi\\Desktop\\txtOut\\"; */

//std::int64_t packetOperation::packetCount = 0;
//vector<PacketInfo> packetOperation::packets;

using namespace std;

/*
__attribute ,derleyiciye struct'ı nasıl düzenleneceği ve hizalanacağı talimatlarını verir.Performans arttırır.
packed -> bellekte boşluk bırakılmadan yerleştirilir.
aligned -> verilen değerin katlarına göre bayt olarak adresler.
deprecated -> yapının kullanılmadığını belirtir.
*/

struct __attribute__((packed, aligned(4))) ipheader {
    unsigned char      iph_ihl : 4, // IP başlığı uzunluğu
        iph_ver : 4; // IP versiyonu
    unsigned char      iph_tos;   // Hizmet tipi
    unsigned short int iph_len;   // Toplam uzunluk
    unsigned short int iph_ident; // Tanımlayıcı
    unsigned short int iph_flag : 3, // Bayraklar
        iph_offset : 13; // Parça offseti
    unsigned char      iph_ttl;   // Yaşam süresi
    unsigned char      iph_protocol; // Protokol
    unsigned short int iph_chksum; // Başlık checksum
    struct  in_addr    iph_sourceip; // Kaynak IP adresi
    struct  in_addr    iph_destip;   // Hedef IP adresi
};

struct __attribute__((packed, aligned(4))) ethHeader {
    u_char destMac[6];
    u_char sourceMac[6];
    u_short eType; // Ethernet türü
};


struct __attribute__((packed, aligned(4))) tcphdr {
    u_short th_sport;     // Kaynak port numarası
    u_short th_dport;     // Hedef port numarası
    uint32_t th_seq;     // Dizi numarası
    uint32_t th_ack;     // Onay numarası
    u_char th_offx2;      // Veri ofseti, rezerve edilmiş alanlar ve flags
    u_char th_flags;      // Kontrol flagları
    u_short th_win;       // Pencere boyutu
    u_short th_sum;       // Checksum
    u_short th_urp;       // Acil işlem göstergesi
};


struct __attribute__((packed, aligned(4))) udphdr {
    u_short uh_sport;   // Kaynak port numarası
    u_short uh_dport;   // Hedef port numarası
    u_short uh_ulen;    // Toplam uzunluk
    u_short uh_sum;     // Checksum
};




packetOperation::packetOperation(const string &path)
    : filePath(path),
    objStartTime(chrono::system_clock::now()),
    controlOpen(false),
    handle(nullptr),
    defaultPath ("C:\\Users\\remzi\\Desktop\\parseSession\\"),
    defaultCsvPath ("C:\\Users\\remzi\\Desktop\\csvOut\\"),
    defaultTxtPath ("C:\\Users\\remzi\\Desktop\\txtOut\\"),
    pCount(0),
    streamIndex(0){
    cout << "Constructor " << endl;

    while(true){
        auto modifyDate = filesystem::last_write_time(path);
        auto fileTime = chrono::time_point_cast<chrono::system_clock::duration>(modifyDate-filesystem::file_time_type::clock::now() + chrono::system_clock::now());
        auto duration = chrono::system_clock::now() - fileTime;
        auto subSeconds = chrono::duration_cast<chrono::seconds>(duration).count();

        if(subSeconds >= 4){
            cout << "Simdiki zaman ile modify date farkı : " << subSeconds << endl;
            break;
        }
        cout << "Dosya yazma islemi devam ediyor , modify date  : " << subSeconds << endl;
        QThread::sleep(2);
    }

    /*auto modifyDate = filesystem::last_write_time(path);
    auto fileTime = chrono::time_point_cast<chrono::system_clock::duration>(modifyDate-filesystem::file_time_type::clock::now() + chrono::system_clock::now());
    auto duration = chrono::system_clock::now() - fileTime;
    auto subSeconds = chrono::duration_cast<chrono::seconds>(duration).count();

    while(subSeconds <= 2){
        cout << "Dosyaya yazma işlemi devam ediyor ..." << endl ;
        //this_thread::sleep_for(chrono::milliseconds(1000));
        QThread::sleep(2);

        auto modifyDate = filesystem::last_write_time(path);
        auto fileTime = chrono::time_point_cast<chrono::system_clock::duration>(modifyDate-filesystem::file_time_type::clock::now() + chrono::system_clock::now());
        auto duration = chrono::system_clock::now() - fileTime;
        auto subSeconds = chrono::duration_cast<chrono::seconds>(duration).count();
    }*/


    splitPath(path);
    //sessionHash = runTshark();
    try {
        this->handle = pcap_open_offline(this->filePath.c_str(),this->errbuf);
        if (this->handle == NULL) {
            std::cerr << "PCAP dosyasi acilamadi : " << this->errbuf << endl;
            controlOpen = false;
        }
        else {
            cout << "Basarili" << endl;
            controlOpen = true;
            /*this->searchMap = new SearchMapWorker(this->fileName.substr(0, this->fileName.find_last_of('.')));
            QThread* cThread = new QThread;
            this->searchMap->moveToThread(cThread);

            QObject::connect(cThread,&QThread::started,searchMap,&SearchMapWorker::controlMap);
            QObject::connect(searchMap,&SearchMapWorker::finished,cThread,&QThread::quit);
            QObject::connect(searchMap,&SearchMapWorker::finished,searchMap,&SearchMapWorker::deleteLater);
            QObject::connect(cThread,&QThread::finished,cThread,&QThread::deleteLater);
            cThread->start();*/
            this->pMap = new pSearchMapWorker(this->fileName.substr(0, this->fileName.find_last_of('.')));
            pthread_t pT;
            pthread_create(&pT,nullptr,pSearchMapWorker::startThread,&this->pMap);
            pthread_detach(pT);


        }
    } catch (const std::exception& ex){
        cerr << "Bilinmeyen Hata :" << ex.what() << endl;
    }
}

packetOperation::~packetOperation(){
    cout << "Destructor" << endl;

    //this->searchMap = nullptr;
    if(handle != nullptr){
        //pcap_close(handle);
        handle = nullptr;
    }
    //packets.clear();
    //packetCount=0;

    //thread başlangıcını kodla
    MoveWorker* mw =new MoveWorker(filePath.c_str());
    QThread* wThread = new QThread;
    mw->moveToThread(wThread);

    QObject::connect(wThread,&QThread::started,mw,&MoveWorker::moveFile);
    QObject::connect(mw,&MoveWorker::moveFinished,wThread,&QThread::quit);
    QObject::connect(mw,&MoveWorker::moveFinished,mw,&MoveWorker::deleteLater);
    QObject::connect(mw,&MoveWorker::failedMove,[this](){
        cout <<"Dosya tasinamadı , hata mevcut tekrar deneniyor .." << endl;
        filesystem::path sPath(this->filePath);
        filesystem::path dPath = filesystem::path("C:\\Users\\remzi\\Desktop\\usedFile") / this->fileName;
        cout << dPath << endl;
        try{
            filesystem::rename(sPath,dPath);
            cout << "Dosya tasindi" << endl;
        }catch(const filesystem::filesystem_error& fError){
            cout << "Dosya tasinamadi , hata :" << fError.what() << endl;
        }
    });
    QObject::connect(mw,&MoveWorker::failedMove,mw,&MoveWorker::deleteLater);
    QObject::connect(wThread,&QThread::finished,wThread,&QThread::deleteLater);
    wThread->start();
    wThread->wait();

    chrono::duration<double> sub = chrono::system_clock::now() - objStartTime;
    cout << this->fileName << " dosyasinin paket islem süresi : " << sub.count() << " saniye ." << endl ;
    this->noStaticPackets.clear();
    this->pCount = 0;
    this->pMap = nullptr;
}

void packetOperation::packetCapture(int loopcount){
    //cout<< "PacketCapture" << endl;
    if(controlOpen!=true){
        cerr << "Geçerli dosya seçiniz !!";
    }else{
        cout << "Paket yakalama basliyor" << endl;
        pcap_handler qHand = reinterpret_cast<pcap_handler>(&packetOperation::processPacket);
        u_char* userData = reinterpret_cast<u_char*>(this);
        pcap_loop(this->handle,loopcount,qHand,userData);
        pcap_close(this->handle);
        this->pMap->setIsLastPacket(true);
        //this->searchMap->setisLastPacket(true);
        //this->searchMap->updateMap(this->sessionMap,true);
        cout << "Toplam yakalanan paket sayisi : " << pCount << endl;
    }
}


void packetOperation::processPacket(void *user, const pcap_pkthdr *header, const u_char *pkt_data)  {
    //cout<< "processPacket" << endl;

    packetOperation* noStatic = reinterpret_cast<packetOperation*>(user);
    string tms = to_string(header->ts.tv_sec) + "." + to_string(header->ts.tv_usec) ;
    (noStatic->pCount)++;
    //cout << tms << endl;

    //cout << "NO STATİC :" << noStatic->pCount << endl;

    struct ipheader* ip_header = (struct ipheader*)(pkt_data + ETHERNET_HEADER_LENGTH);
    struct ethHeader* eth_header = (struct ethHeader*)pkt_data;

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->iph_sourceip), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->iph_destip), dest_ip, INET_ADDRSTRLEN);

    stringstream sMac;
    for (int k = 0; k < 6; ++k) {
        sMac << hex << uppercase << std::setw(2) << setfill('0') << static_cast<int>(eth_header->sourceMac[k]);
        if (k < 5) {
            sMac << ":";
        }
    }

    stringstream dMac;
    for (int l = 0; l < 6; ++l) {
        dMac << hex << uppercase << std::setw(2) << setfill('0') << static_cast<int>(eth_header->destMac[l]);
        if (l < 5) {
            dMac << ":";
        }
    }
    PacketInfo pInfo;
    pInfo.sourceIP = source_ip;
    pInfo.destIP = dest_ip;
    pInfo.sourceMac = sMac.str();
    pInfo.destMac = dMac.str();
    pInfo.timestamp = tms;
    pInfo.packetLen = header->len ;

    //++packetCount;
    //cout << "Paket Number : " << packetCount << endl;
    //cout << "Source IP : " << source_ip << endl;
    //cout << "Source MAC : ";
    for (int k = 0; k < 6; ++k) {
        //cout << hex << uppercase << static_cast<int>(eth_header->sourceMac[k]);
        if (k < 5) {
            //cout << ":";
        }
    }
    //cout  << endl;

    //cout << "Destination IP : " << dest_ip << endl;

    //cout << "Destination MAC : ";
    for (int i = 0; i < 6; ++i) {
        //cout << hex << uppercase << static_cast<int>(eth_header->destMac[i]);
        if (i < 5) {
            //cout << ":";
        }
    }
    //cout << endl;
    std::vector<u_char> packetData(pkt_data,pkt_data+header->caplen);
    noStatic->packets.push_back(packetData);
    noStatic->headers.push_back(*header);
    noStatic->pMap->setPacketsInfo(pkt_data,header);
    //noStatic->searchMap->setPacketsInfo(pkt_data,header);


    if (ip_header->iph_protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(pkt_data + ETHERNET_HEADER_LENGTH + sizeof(struct ipheader));
        //cout << "Source Port (TCP): " << std::dec << ntohs(tcp_header->th_sport) << endl;
        //cout << "Destination Port (TCP): " << std::dec << ntohs(tcp_header->th_dport) << endl;
        //payload bilgileri
        /*int tcp_header_size= tcp_header->th_offx2 * 4;
        const u_char* payload = pkt_data + ETHERNET_HEADER_LENGTH + sizeof(struct ipheader) + tcp_header_size;
        int payload_length = header->caplen - (ETHERNET_HEADER_LENGTH + sizeof(struct ipheader) + tcp_header_size);*/

        pInfo.sourcePort = ntohs(tcp_header->th_sport);
        pInfo.destPort = ntohs(tcp_header->th_dport);
        pInfo.protocol = "TCP";
        noStatic->createSessionMap(pInfo,packetData,header);

    }
    else if (ip_header->iph_protocol == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(pkt_data + ETHERNET_HEADER_LENGTH + sizeof(struct ipheader));
        //cout << "Source Port (UDP): " << std::dec << ntohs(udp_header->uh_sport) << endl;
        //cout << "Destination Port (UDP): " << std::dec << ntohs(udp_header->uh_dport) << endl;
        //payload bilgileri
        /*int udp_header_size = 8 ; // udp başlık boyutu sabit
        const u_char* payload = pkt_data + ETHERNET_HEADER_LENGTH + sizeof(struct ipheader) + udp_header_size;
        int payload_length = header->caplen - (ETHERNET_HEADER_LENGTH + sizeof(struct ipheader) + udp_header_size);*/

        pInfo.sourcePort = ntohs(udp_header->uh_sport);
        pInfo.destPort = ntohs(udp_header->uh_dport);
        pInfo.protocol = "UDP";
    }

    //findSessionList(pInfo);
    //cout << "Protokol :" << pInfo.protocol ;
    //cout << endl;
    noStatic->noStaticPackets.push_back(pInfo);

    //packets.push_back(pInfo);

}


void packetOperation::splitPath(const string &str){
    //cout << "splitPath" << endl;
    vector<string> tokens;
    string delimiter = "/";
    size_t start = 0, end = 0;
    while ((end = str.find(delimiter, start)) != string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
    }
    tokens.push_back(str.substr(start));
    fileName = tokens[tokens.size() - 1];
    for (size_t i = 0; i < tokens.size()-1; i++) {
        directory += tokens[i] + delimiter ;
    }

    /*for (const auto& token : tokens) {
        cout << token << std::endl;
    }*/
    cout << "Filename :" << fileName << endl ;
    cout << "Dİrectory : "<< directory << endl;
}



void packetOperation::printPacketInfo(){
    //cout << "printPacketInfo" << endl;
    //cout << "Paket Sayisi :" << noStaticPackets.size() << endl;
    cout << "Pcap dosyası :" << filePath << endl;
    cout << "Dosya Adi :" << fileName << endl;
    cout << "Dizin Adi :" << directory << endl;
    int pos = fileName.find_last_of('.');
    string ethernetTxtName = defaultTxtPath + fileName.substr(0, pos) + "Ethernet.txt";
    string sessionTxtName = defaultTxtPath + fileName.substr(0, pos) + "Session.txt";
    //cout << "ethernetTxtName : " << ethernetTxtName << endl;
    //cout << "sessionTxtName : " << sessionTxtName << endl;

    ofstream ethernetDosya(ethernetTxtName);
    if (!ethernetDosya.is_open()) {
        cerr << "ethernetDosya açılamadı!" << std::endl;
    }

    ofstream sessionDosya(sessionTxtName);
    if (!sessionDosya.is_open()) {
        cerr << "sessionDosya açılamadı!" << std::endl;
    }

    //------------------
    int packetNumCounter = 0 ;
    for (const auto& p : noStaticPackets) {
        packetNumCounter++;
        ethernetDosya << packetNumCounter << " - " << p.sourceIP << " - " << p.sourcePort << " - " << p.destIP << " - " << p.destPort << " - " <<  p.protocol  << " - " << p.timestamp << endl;
        sessionDosya << packetNumCounter << " - " << p.sourceMac << " - " << p.destMac << " - " << p.timestamp << endl;
    }

    ethernetDosya.close();
    sessionDosya.close();

    /*for (auto& pair : sessionHash) {
        cout << "Paket: " << pair.first << ", Session ID: " << pair.second << endl;
    }*/
    cout << " printPacketInfo bitti" << endl;
}



void packetOperation::createSessionMap(const PacketInfo &p,const std::vector<u_char> &pData, const pcap_pkthdr *header){
    //auto start = std::chrono::high_resolution_clock::now();
    vector<string> searchString = {p.sourceIP + "-" + to_string(p.sourcePort) + "-" + p.destIP + "-" + to_string(p.destPort),
                                   p.destIP + "-" + to_string(p.destPort) + "-" + p.sourceIP + "-" + to_string(p.sourcePort) };
    size_t directionKey = 0;


    //paket yönlerine göre boyutlar hesaplanacak (half session - flow )
    bool isFound = false ;
    for(auto i=searchString.cbegin();i!=searchString.cend();i++){
        //cout << *i << endl;
        auto searchIt = sessionMap.find(*i);
        if(searchIt != sessionMap.end()){
            isFound = true;
            searchIt->second.packetCount +=1 ;
            searchIt->second.packetsLen += p.packetLen;
            searchIt->second.endTime = p.timestamp;
            searchIt->second.packetIndex.push_back(this->pCount);
            if(directionKey==0){
                searchIt->second.sourceTodest += 1;
                searchIt->second.sourceTodestLen += p.packetLen;
            }else{
                searchIt->second.destToSource += 1 ;
                searchIt->second.destToSourceLen += p.packetLen;
            }
            SessıonInfo& newsI = searchIt->second;

            this->pMap->updateSessionMap(*i,newsI);
            //this->searchMap->updateSessionMap(*i,newsI);
            break;
        }
        directionKey++;
    }


    if(isFound!=true){
        SessıonInfo nSession = {p.sourceIP,
                                p.destIP,
                                p.sourcePort,
                                p.destPort,
                                this->streamIndex,
                                1,
                                p.packetLen,
                                1,
                                p.packetLen,
                                0,
                                0,
                                p.timestamp,
                                p.timestamp,
                                {pCount}};
        sessionMap[searchString.front()] = nSession;

        //this->pMap->updateSessionMap(searchString.front(),nSession);
        //this->searchMap->updateSessionMap(searchString.front(),nSession);
        this->streamIndex += 1 ;
        //sessionMap.insert()
        //end time kontrolü ile dosyaya yazma
        //session bittiğini nasıl anlarız .Tcp ve Udp ayrı ayrı
        //ana pencereye bar ekle progressbar
        //splitcap
    }
    //searchMap->updateMap(this->sessionMap,false,this->packets,this->headers);
    //auto end = std::chrono::high_resolution_clock::now(); // Bitiş zamanı
    //std::chrono::duration<double> elapsed = end - start; // Geçen süre
    //cout << "createSessionMap fonksiyonu " << elapsed.count() << " saniyede çalıştı." << endl;
}




void packetOperation::printSessionMap(){
    string name = this->fileName.substr(0, this->fileName.find_last_of('.'));
    string mkCommand = "mkdir " + this->defaultPath + name ;

    int dirConrol = system(mkCommand.c_str());
    if (dirConrol==0){
        this->defaultPath += name + "\\";
    }
    for (auto it = sessionMap.cbegin(); it != sessionMap.cend(); ++it){
        const string& txtName = this->defaultPath + it->first +".txt";
        const SessıonInfo& sI = it->second;
        ofstream mapTxt(txtName);
        if(!mapTxt){
            cerr << "Dosya açılamadı " << endl;
        }
        mapTxt << "Source IP :" << sI.sourceIP << "\n"
               << "Destination IP :" << sI.destIP << "\n"
               << "Source Port :" << sI.sourcePort << "\n"
               << "Destination Port :" << sI.destPort << "\n"
               << "Stream Index :" << sI.streamIndex << "\n"
               << "Packets Count :" << sI.packetCount << "\n"
               << "Total Len :" << sI.packetsLen << "\n"
               << "Source To Destination :" << sI.sourceTodest << "\n"
               << "Source To Destination Length :" << sI.sourceTodestLen << "\n"
               <<"Destination To Source :" << sI.destToSource << "\n"
               <<"Destination To Source Length :" << sI.destToSourceLen << "\n"
               << "Start Time :" << sI.startTime << "\n"
               << "End Time :" << sI.endTime << endl;

    }

}

void packetOperation::printCsvFile(){

    string name = this->defaultCsvPath + this->fileName.substr(0, this->fileName.find_last_of('.')) + ".csv";

    ofstream csvFile(name);
    if(!csvFile.is_open()){
        cerr << "CSV acilmadi !!" << endl;
    }
    csvFile << "Source IP;Destination IP;"
               "Source Port;Destination Port;"
               "Stream Index;Packets Count;"
               "Total Len;Source To Destination;"
               "Source To Destination Length;"
               "Destination To Source;Destination To Source Length;"
               "Start Time;End Time\n";

    for(auto it = sessionMap.cbegin();it!=sessionMap.cend();++it){

        const SessıonInfo& value = it->second;
        csvFile << value.sourceIP << ';' << value.destIP
                << ';' << value.sourcePort << ';' << value.destPort << ';' << value.streamIndex
                << ';' << value.packetCount << ';' << value.packetsLen << ';' << value.sourceTodest
                << ';' << value.sourceTodestLen << ';' << value.destToSource << ';' << value.destToSourceLen
                << ';' << value.startTime << ';' << value.endTime << "\n";
    }
    csvFile.close();
    //cout << name << " printCsvFile yazildi" << endl;

}








//günceli yazıldı kaldırılacak
void packetOperation::findSessionList(const PacketInfo& packetInfo,int cnt){
    // sessiid karşılığında paket bilgisi verir
    //cout <<packetInfo.destIP<< " - " << cnt << endl;
    //cout <<"index map :" << this->indexMap.size()<< endl;
    bool control = false;

    //unordered_map<int,SessionData> indexMap;
    //map hızını kullan , packetcount -start time -end time - mergecap -syclomatic completix - static lib -
    //map-find -map indeks- session key - .compare - (end-start) -
    //session bilgi tek satır
    //modify date

    if(indexMap.empty()){
        indexMap[0] = {packetInfo.sourceIP,
                       packetInfo.destIP,
                       packetInfo.sourcePort,
                       packetInfo.destPort,
                       packetInfo.protocol,
                       {cnt}};
        streamIndex++;
    }else{
        for(auto it = this->indexMap.begin();it!=this->indexMap.end();it++){
            auto& session = it->second;
            if(((packetInfo.sourceIP == session.sourceIp || packetInfo.sourceIP == session.destIp) &&
                 (packetInfo.sourcePort == session.sourcePort || packetInfo.sourcePort == session.destPort) &&
                 (packetInfo.destIP == session.destIp || packetInfo.destIP == session.sourceIp) &&
                 (packetInfo.destPort == session.destPort || packetInfo.destPort == session.sourcePort)
                 )){
                it->second.index.push_back(cnt);
                //cout << "Var" << endl;
                control = true;
                break;
            }
        }
        if(!control){
            indexMap[streamIndex] = {packetInfo.sourceIP,
                                     packetInfo.destIP,
                                     packetInfo.sourcePort,
                                     packetInfo.destPort,
                                     packetInfo.protocol,
                                     {cnt}};
            streamIndex++;
        }
    }
}




void packetOperation::printSessionList(){
    //güncel session listesini yazdıran fonk

    string name = this->fileName.substr(0, this->fileName.find_last_of('.'));
    string mkCommand = "mkdir " + this->defaultPath + name ;

    int dirConrol = system(mkCommand.c_str());
    if (dirConrol==0){
        this->defaultPath += name + "\\";
    }
    for(const auto& [k,v] :this->indexMap){
        string txtName = this->defaultPath + v.sourceIp + "_" +
                         to_string(v.sourcePort) + "_" +
                         v.destIp + "_" +
                         to_string(v.destPort) + "_" +
                         "Session" +
                         to_string(k) + ".txt";
        ofstream sFile(txtName);
        if(!sFile){
            cerr << "Dosya acilmadı " << endl;
        }
        for(int id : v.index){
            sFile << id << "-" << this->noStaticPackets[id-1].sourceIP << " - "
                  << this->noStaticPackets[id-1].sourceMac << " - "
                  << this->noStaticPackets[id-1].sourcePort << " - "
                  << this->noStaticPackets[id-1].destIP << " - "
                  << this->noStaticPackets[id-1].destMac << " - "
                  << this->noStaticPackets[id-1].destPort << " - "
                  << this->noStaticPackets[id-1].timestamp
                  << endl ;
        }
        sFile.close();
    }

    cout << "Session List yazıldı . " << std::endl;

}











// kaldırılacaklar
unordered_map<string,vector<string>> packetOperation::runTshark(){
    cout << "RunTshark" << endl ;
    string tsharkFileName = defaultCsvPath + this->fileName.substr(0, this->fileName.find_last_of('.')) + ".txt";
    string mkCommand = "mkdir " + defaultPath +  this->fileName.substr(0, this->fileName.find_last_of('.'));
    string command = "tshark -r " + this->directory + this->fileName + " -T fields "
                                                                       "-e tcp.stream -e frame.number "
                                                                       "-e ip.src -e tcp.srcport "
                                                                       "-e ip.dst -e tcp.dstport > " + tsharkFileName; // start /B cmd /c  denendi çalışmıyor arka planda çalışması için

    int commandResult = system(command.c_str());
    vector<string> dosya;
    if (commandResult == 0) {
        cout << "Komut başarıyla çalıştı." << endl;
            ifstream tFile (tsharkFileName);
        if (!tFile) {
            cerr << "Dosya açılamadı!" << endl;
        }else{
            string line ;
            while(getline(tFile,line)){
                dosya.push_back(line);
            }
        }
        tFile.close();
    } else {
        cout << "Komut çalıştırılamadı." << endl;
    }
    //unordered_map<string,string> sessionIndeks;
    unordered_map<string,vector<string>> sessionIndeks;
    for (const std::string& satir : dosya) {
        std::istringstream ss(satir);
        std::string parca,sessionId,paketNum;

        getline(ss, sessionId, '\t'); //session id
        //cout << sessionId << "-";
        getline(ss, paketNum, '\t'); // paket numara
        //cout << paketNum << endl;
        //sessionIndeks[paketNum] = sessionId;
        sessionIndeks[sessionId].push_back(paketNum);
    }

    cout << "Toplam Session Sayısı : " << sessionIndeks.size() << endl ;

        int dirConrol = system(mkCommand.c_str());
    if (dirConrol==0){
        cout << "Dizin olusturuldu " << endl;
        defaultPath = defaultPath +  this->fileName.substr(0, this->fileName.find_last_of('.')) + "\\";
        cout << "DefaultPath : " << defaultPath << endl;
    }
    return sessionIndeks;
}



void packetOperation::printSessionIndeks(){
    cout << "printSessionIndeks" << endl;
    //string defaultPath = "C:/Users/remzi/Desktop/sessionOut/";
    string name = fileName.substr(0,fileName.find_last_of('.'));
    for(const auto& ss : this->sessionHash){
        //cout << "Session Id :" << ss.first << endl ;
        string sessionFileName = defaultPath
                                 +name + "Session"
                                 + ss.first +".txt"; //name + '/'+
        //cout << sessionFileName << endl ;
        ofstream sessionIndeksDosya(sessionFileName);
        if (!sessionIndeksDosya.is_open()) {
            cerr << "sessionDosya açılamadı!" << errno << ", Hata mesajı: " << strerror(errno) << endl ;
        }
        const vector<string>& paketler = ss.second;
        //cout << "Paketler : ";
        for (const string& p:paketler){
            int paketInde = std::stoi(p);
            sessionIndeksDosya << noStaticPackets[paketInde].sourceIP
                               << " - " << noStaticPackets[paketInde].sourcePort
                               << " - " << noStaticPackets[paketInde].destIP
                               << " - " << noStaticPackets[paketInde].destPort
                               << " - " << noStaticPackets[paketInde].sourceMac
                               << " - " << noStaticPackets[paketInde].destMac
                               << " - " <<  noStaticPackets[paketInde].protocol
                               << " - " << paketInde
                               << endl;
            //cout << " " << p;
        }
        sessionIndeksDosya.close();
        //cout << endl;
        //cout << sessionFileName << endl;
    }
    //this->fileName kullan
}

