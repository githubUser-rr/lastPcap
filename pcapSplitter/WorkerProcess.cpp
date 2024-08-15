#include "WorkerProcess.h"

#include <QFileInfo>
#include <QString>
#include <string>
#include <QMessageBox>
#include <QDebug>

WorkerProcess::WorkerProcess(std::string fName) : fileName(fName) {
    this->packet = new readAndProcessPacket(this->fileName);
}

WorkerProcess::~WorkerProcess(){
    qDebug() << "WorkerProcess destructor" ;
    delete this->packet;

}

void WorkerProcess::updateInfoText(){
    int count = packet->getPacketCount();
    qDebug() << count;
    QFileInfo fInfo(QString::fromStdString(this->fileName));
    double fSize = fInfo.size()/ (1024.0 * 1024.0);
    std::string pcapName = fileName.substr(fileName.find_last_of('/') + 1, fileName.find_last_of('.') - fileName.find_last_of('/') - 1);

    QString ınfoText = ("%1 pcap dosyasının : \n\nToplam boyutu : %2\ MB\nToplam paket sayısı : %3 ");
    setTxt = ınfoText.arg(QString::fromStdString(pcapName)).arg(fSize, 0, 'f', 2).arg(count);
    //u->infoPacket->setText(setTxt);
    //QMessageBox::warning(nullptr,"INFO",setTxt,QMessageBox::Ok);

    qDebug() << setTxt ;
    emit readFinished();

}

void WorkerProcess::parseForSizeWorker(){
    this->packet->parseForPacketSize(this->destDirec,this->cParam*1048576);
    /*u->infoPacket->clear();
    u->lineEdit->clear();
    u->radioButton->setChecked(false);
    u->label->clear();
    u->radioButton->setChecked(false);*/
    emit finished();
}

void WorkerProcess::parseForPacketCountWorker(){
    this->packet->parseForPacketCount(cParam,destDirec);
    /*u->lineEdit->clear();
    u->infoPacket->clear();
    u->label->clear();
    u->label->clear();
    u->packetNum->setChecked(false);*/
    emit finished();
}

void WorkerProcess::parseForFile(){
    this->packet->printPackets(destDirec,this->cParam);
    /*u->infoPacket->clear();
    u->lineEdit->clear();
    u->label->clear();
    u->fileNum->setChecked(false);*/
    emit finished();

}

void WorkerProcess::parseForTotalSizeWorker(){
    this->packet->parseForTotalSize(destDirec,this->cParam);
    /*u->infoPacket->clear();
    u->lineEdit->clear();
    u->label->clear();
    u->fileNum->setChecked(false);*/
    emit finished();
}

void WorkerProcess::setCPram(int control){
    this->cParam = control;
}

void WorkerProcess::setDestDirec(std::string director){
    this->destDirec = director;
}

