#include "readAndProcessPacket.h"

#include <iostream>
#include <string>

using namespace std;
//dosya sayısına 2 koşul ekle , paket sayısı ve mb boyutu eklencek
readAndProcessPacket::readAndProcessPacket(std::string fName) :fileName(fName) ,packetCount(0),totalByte(0) {
    this->pcapName = fileName.substr(fileName.find_last_of('/') + 1, fileName.find_last_of('.') - fileName.find_last_of('/') - 1);
    try {
        this->handle = pcap_open_offline(this->fileName.c_str(),this->errbuf);
        if (this->handle == NULL) {
            std::cerr << "PCAP dosyasi acilamadi : " << this->errbuf << endl;
            controlOpen = false;
        }
        else {
            cout << "Basarili" << endl;
            controlOpen = true;
            this->processPacket();
            cout << "Dosya adı : " << this->pcapName  <<std::endl;
        }
    } catch (const std::exception& ex){
        cerr << "Bilinmeyen Hata :" << ex.what() << endl;
    }
}

readAndProcessPacket::~readAndProcessPacket(){
    if(this->handle != nullptr){
        pcap_close(this->handle);
        //this->handle = nullptr;
    }
    this->packets.clear();

}

void readAndProcessPacket::processPacket() {
    if (!controlOpen || this->handle == nullptr) {
        std::cerr << "PCAP dosyası açık değil veya handle geçersiz" << std::endl;
            return;
    }

    int pCount = 0;
    struct pcap_pkthdr* header;
    const u_char* data;
    int result;

    while ((result = pcap_next_ex(this->handle, &header, &data)) >= 0) {
        if (result == 0) {
            // timeout
            continue;
        }
        this->totalByte += header->len;

        std::vector<u_char> packet_data(data, data + header->caplen);
        packets.push_back(packet_data);
        headers.push_back(*header);
        ++pCount;
    }

    if (result == -1 || result == PCAP_ERROR ) {
        std::cerr << "PCAP okuma hatası: " << pcap_geterr(this->handle) << std::endl;
    }
    std::cout << "Toplam paket: " << packets.size() << std::endl;
    std::cout << "Boyut: " << this->totalByte << std::endl;
    this->packetCount = pCount;
}




int readAndProcessPacket::getPacketCount() const {
    return this->packetCount;
}

void readAndProcessPacket::printPackets(std::string destDirec,int packetSize){

    if(this->handle == nullptr){
        cout << "nulpptr hatası" << endl;
    }else{
        cout  << "handle null degil " << endl;
    }

    //std::cout << "printPackets()" << destDirec <<std::endl;
    int pcapSize = packets.size() / packetSize;
    int lastPackets = packets.size() % packetSize;
    int start = 0;

    for(int i=0;i<packetSize;i++){
        int currPart = pcapSize + (i < lastPackets ? 1:0);

        std::string newFile = destDirec+"/"+this->pcapName+"_"+std::to_string(i)+".pcap";
        pcap_dumper_t *file = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535),newFile.c_str());

        if(file == nullptr) {
            cerr << "Dosya hhatası" << newFile << endl;
            //pcap_close(file);
        }
        /*header.caplen = 0;
        header.len = 0;*/

        int writtenPacket = 0;
        for(int j=0 ;j<currPart;++j){
            /*            struct pcap_pkthdr header;
            header.len = header.caplen = packets[start+j].size();*/

            const pcap_pkthdr& header = this->headers[start+j];
            const std::vector<u_char>& packet = this->packets[start+j];
            pcap_dump(reinterpret_cast<u_char*>(file),&header,packet.data());
            writtenPacket++;

        }

        pcap_dump_close(file);
        cout << newFile << " dosyasına " << writtenPacket <<" paket yazıldı" << endl;
        start += currPart;
    }

}

void readAndProcessPacket::parseForPacketCount(int pCount,std::string dDirec){
    if (this->handle == nullptr) {
        std::cerr << "handle is nullptr" << std::endl;

    } else {
        std::cout << "handle is not nullptr" << std::endl;
    }

    int fileNumber = (packets.size() + pCount - 1) / pCount;

    int start = 0;
    int total = packets.size();
    for(int i=0;i<fileNumber;++i){
        int currPart = std::min(pCount,total-start);
        std::string newFile = dDirec + "/" + this->pcapName + "_" + std::to_string(i) + ".pcap";
        pcap_dumper_t *file = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), newFile.c_str());

        if (file == nullptr) {
            std::cerr << "File error: " << newFile << std::endl;
            continue;
        }

        int writtenPacket = 0;
        for(int j=0;j<currPart;++j){
            const pcap_pkthdr& header = this->headers[start + j];
            const std::vector<u_char>& packet = this->packets[start + j];
            pcap_dump(reinterpret_cast<u_char*>(file), &header, packet.data());
            writtenPacket++;
        }
        pcap_dump_close(file);
        cout << newFile << " dosyasına " << writtenPacket <<" paket yazıldı" << endl;
        start += currPart;
    }

}

void readAndProcessPacket::parseForPacketSize(std::string destDirec, int packetMB){
    if (this->handle == nullptr) {
        std::cout << "null pointer hatası" << std::endl;
            return;
    } else {
        std::cout << "handle null değil" << std::endl;
    }

    int currentByte = 0;
    std::vector<pcap_pkthdr> currentHeaders;
    std::vector<std::vector<u_char>> currentPackets;
    int start = 0 ;
    int fileIndex= 0;
    for(int i=0;i<this->headers.size();++i){
        int pSize = headers[i].len;

        if(currentByte+pSize >= packetMB){ //  büyükse yaz
            std::string newFile = destDirec + "/" + this->pcapName + "_" + std::to_string(fileIndex) + ".pcap";
            pcap_dumper_t *file = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), newFile.c_str());

            if (file == nullptr) {
                std::cerr << "Dosya hata: " << newFile << std::endl;
                continue;
            }

            for (size_t j = 0; j < currentHeaders.size(); ++j) {
                pcap_dump(reinterpret_cast<u_char*>(file), &currentHeaders[j], currentPackets[j].data());
            }

            pcap_dump_close(file);
            std::cout << newFile << " dosyasına " << currentHeaders.size() << " paket yazıldı" << std::endl;
            currentByte = 0;
            currentHeaders.clear();
            currentPackets.clear();
            ++fileIndex;
        }
        currentHeaders.push_back(headers[i]);
        currentPackets.push_back(packets[i]);
        currentByte += pSize;
    }

    if(!currentHeaders.empty()){ // son kalan paketler için
        std::string newFile = destDirec + "/" + this->pcapName + "_" + std::to_string(fileIndex) + ".pcap";
        pcap_dumper_t *file = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), newFile.c_str());

        if (file == nullptr) {
            std::cerr << "Dosya hata: " << newFile << std::endl;
        }

        for (size_t j = 0; j < currentHeaders.size(); ++j) {
            pcap_dump(reinterpret_cast<u_char*>(file), &currentHeaders[j], currentPackets[j].data());
        }
        std::cout << newFile << " dosyasına " << currentHeaders.size() << " paket yazıldı" << std::endl;
        pcap_dump_close(file);
    }
}

void readAndProcessPacket::setDestDirec(std::string dDirec){
    this->destDirec = dDirec;
}

void readAndProcessPacket::parseForTotalSize(std::string destDirec, int fileNum){
    if (this->handle == nullptr) {
        std::cout << "null pointer hatası" << std::endl;
            return;
    } else {
        std::cout << "handle null değil" << std::endl;
    }

    int packetSize = this->totalByte / (fileNum);
    //int remainder = this->totalByte % fileNum ;

    int currentByte = 0;
    std::vector<pcap_pkthdr> currentHeaders;
    std::vector<std::vector<u_char>> currentPackets;
    int start = 0 ;
    int fileIndex= 0;

    for(int i=0;i<this->headers.size();++i){
        int pSize = headers[i].len;

        if((currentByte+pSize > packetSize) && (fileIndex!=fileNum-1)){ //  büyükse yaz
            std::string newFile = destDirec + "/" + this->pcapName + "_" + std::to_string(fileIndex) + ".pcap";
            pcap_dumper_t *file = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), newFile.c_str());

            if (file == nullptr) {
                std::cerr << "Dosya hata: " << newFile << std::endl;
                continue;
            }

            for (size_t j = 0; j < currentHeaders.size(); ++j) {
                pcap_dump(reinterpret_cast<u_char*>(file), &currentHeaders[j], currentPackets[j].data());
            }

            pcap_dump_close(file);
            std::cout << newFile << " dosyasına " << currentHeaders.size() << " paket yazıldı\n"
                      << "Dosya boyutu : " << currentByte+pSize <<std::endl;
            currentByte = 0;
            currentHeaders.clear();
            currentPackets.clear();
            ++fileIndex;
        }
        currentHeaders.push_back(headers[i]);
        currentPackets.push_back(packets[i]);
        currentByte += pSize;
    }

    if(!currentHeaders.empty()){ // son kalan paketler için

        int lastByte = 0 ;

        std::string newFile = destDirec + "/" + this->pcapName + "_" + std::to_string(fileIndex) + ".pcap";
        pcap_dumper_t *file = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), newFile.c_str());

        if (file == nullptr) {
            std::cerr << "Dosya hata: " << newFile << std::endl;
        }

        for (size_t j = 0; j < currentHeaders.size(); ++j) {
            pcap_dump(reinterpret_cast<u_char*>(file), &currentHeaders[j], currentPackets[j].data());
            lastByte+= currentHeaders[j].len;
        }
        std::cout << newFile << " dosyasına " << currentHeaders.size() << " adet son kalan paketler yazıldı\n"
                    << "Dosya boyutu : " << lastByte <<std::endl;
        pcap_dump_close(file);
    }
}
