#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QString>
#include <QFileDialog>
#include <QDir>
#include <QDebug>
#include <QMessageBox>
#include <QIntValidator>
#include <QFileInfo>
#include <QThread>



#include "readAndProcessPacket.h"


mainwindow::mainwindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::mainwindow)
{
    ui->setupUi(this);
    this->control = -1;
    //connect(ui->selectInput,&QPushButton::clicked,this,&mainwindow::on_selectInput_clicked);
    QIntValidator *v = new QIntValidator(this);
    ui->lineEdit->setValidator(v);
    ui->comboBox->setVisible(false);



}

mainwindow::~mainwindow()
{
    delete ui;
}


void mainwindow::on_selectInput_clicked(){
    qDebug() << "Select In";
    pcapFile = QFileDialog::getOpenFileName(nullptr, "Pcap Dosyası Seçiniz", QDir::homePath() + "/Desktop", "Pcap Dosyaları (*.pcap)");

    QString pcapName = pcapFile.mid( pcapFile.lastIndexOf('/') +1 ,pcapFile.lastIndexOf('.') - pcapFile.lastIndexOf('/') - 1);
    qDebug() << pcapName;
    if (!pcapFile.isEmpty()) {
        /*QFileInfo fInfo(pcapFile);
        double fSize = fInfo.size()/ (1024.0 * 1024.0);
        QString ınfoText = ("%1 pcap dosyasının : \n\nToplam boyutu : %2\nToplam paket sayısı : %3 ");
        QString setTxt = ınfoText.arg(pcapName).arg(fSize, 0, 'f', 2).arg(pCount);
        ui->infoPacket->setText(setTxt);*/

        WorkerProcess *worker  = new WorkerProcess(pcapFile.toStdString());
        QThread* thread = new QThread();
        worker->moveToThread(thread);

        connect(thread,&QThread::started,worker,&WorkerProcess::updateInfoText);
        connect(worker,&WorkerProcess::readFinished,this,[this,worker](){
            this->ui->infoPacket->setText(worker->setTxt);
        });
        connect(worker,&WorkerProcess::readFinished,thread,&QThread::quit);
        connect(worker,&WorkerProcess::readFinished,worker,&WorkerProcess::deleteLater);
        connect(thread,&QThread::finished,thread,&QThread::deleteLater);
        thread->start();


        /*QFileInfo fInfo(pcapFile);
        double fSize = fInfo.size()/ (1024.0 * 1024.0);

        this->packet = new readAndProcessPacket(pcapFile.toStdString());
        int pCount = packet->getPacketCount();
        QString ınfoText = ("%1 pcap dosyasının : \n\nToplam boyutu : %2\nToplam paket sayısı : %3 ");
        QString setTxt = ınfoText.arg(pcapName).arg(fSize, 0, 'f', 2).arg(pCount);
        ui->infoPacket->setText(setTxt);

        //delete packet;
        //qDebug() << pCount;*/
    } else {
        QMessageBox::warning(nullptr, "Pcap Dosyası Seçilmedi", "Herhangi bir dosya seçilmedi, dosya seçmek için tekrarlayın.");
    }


}


void mainwindow::on_selectOutput_clicked(){
    QString defaultPath = QDir::homePath() + "/Desktop";
    destDirectory = QFileDialog::getExistingDirectory(this,
                                                          tr("Dizin Seç"),
                                                          defaultPath,
                                                          QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);

    qDebug() << "Dest direc" << destDirectory;



}


void mainwindow::on_radioButton_toggled(bool checked)
{
    //qDebug() << "radio" << checked;
    if(checked){
        ui->label->setText("/mb dosya boyutunu giriniz.");
        this->control = 0;
    }else{
        ui->label->clear();
    }
}


void mainwindow::on_packetNum_toggled(bool checked)
{
    if(checked){
        ui->label->setText("bir .pcap dosyasında kaç paket olacağını giriniz.");
        this->control = 1;
    }else{
        ui->label->clear();
    }
}


void mainwindow::on_fileNum_toggled(bool checked){
    if(checked){
        ui->label->setText(".pcap dosyasını kaç neye göre ve \nkaç dosyaya ayırmak istediğinizi giriniz.");
        ui->comboBox->setVisible(true);
        //std::cout << ui->comboBox->currentIndex() << std::endl;
        this->control = 2;
    }else{
        ui->comboBox->setVisible(false);
        ui->label->clear();
    }
}


void mainwindow::on_runParse_clicked(){
    //this->packet->setDestDirec(destDirectory.toStdString());
    QString txt = ui->lineEdit->text();
    int number = txt.toInt();
    qDebug() << number;
    qDebug() << this->control;

    switch (this->control) {
    case 0:
        if(this->destDirectory.isEmpty() || number <=0 ){
            QMessageBox::warning(nullptr,"HATA !","Hedef dizin seçilmedi veya\n0'dan büyük sayı giriniz..",QMessageBox::Ok);
        }else{

            WorkerProcess *worker  = new WorkerProcess(pcapFile.toStdString());
            worker->setCPram(number);
            worker->setDestDirec(this->destDirectory.toStdString());
            QThread* thread = new QThread();
            worker->moveToThread(thread);

            connect(thread,&QThread::started,worker,&WorkerProcess::parseForSizeWorker);
            connect(worker,&WorkerProcess::finished,thread,&QThread::quit);
            connect(worker,&WorkerProcess::finished,worker,&WorkerProcess::deleteLater);
            connect(thread,&QThread::finished,thread,&QThread::deleteLater);
            thread->start();
            ui->radioButton->setChecked(false);

            /*this->packet->parseForPacketSize(this->destDirectory.toStdString(),number*1048576);
            delete this->packet;
            ui->infoPacket->clear();
            ui->lineEdit->clear();
            this->destDirectory.clear();
            ui->radioButton->setChecked(false);
            ui->label->clear();
            ui->radioButton->setChecked(false);*/
        }
        break;
    case 1:
        if(this->destDirectory.isEmpty() || number <=0 ){
            QMessageBox::warning(nullptr,"HATA !","Hedef dizin seçilmedi veya\n0'dan büyük sayı giriniz..",QMessageBox::Ok);
        }else{
            WorkerProcess *worker  = new WorkerProcess(pcapFile.toStdString());
            worker->setCPram(number);
            worker->setDestDirec(this->destDirectory.toStdString());
            QThread* thread = new QThread();
            worker->moveToThread(thread);

            connect(thread,&QThread::started,worker,&WorkerProcess::parseForPacketCountWorker);
            connect(worker,&WorkerProcess::finished,thread,&QThread::quit);
            connect(worker,&WorkerProcess::finished,worker,&WorkerProcess::deleteLater);
            connect(thread,&QThread::finished,thread,&QThread::deleteLater);
            thread->start();

            ui->packetNum->setChecked(false);



            /*this->packet->parseForPacketCount(number,this->destDirectory.toStdString());
            delete this->packet;
            ui->lineEdit->clear();
            ui->infoPacket->clear();
            ui->label->clear();
            this->destDirectory.clear();
            ui->label->clear();
            ui->packetNum->setChecked(false);*/
        }
        break;
    case 2:
        if(this->destDirectory.isEmpty() || number <=0 ){
            QMessageBox::warning(nullptr,"HATA !","Hedef dizin seçilmedi veya\n0'dan büyük sayı giriniz..",QMessageBox::Ok);
        }else{

            WorkerProcess *worker  = new WorkerProcess(pcapFile.toStdString());
            worker->setCPram(number);
            worker->setDestDirec(this->destDirectory.toStdString());
            QThread* thread = new QThread();
            worker->moveToThread(thread);

            if(ui->comboBox->currentIndex()==0){
                connect(thread,&QThread::started,worker,&WorkerProcess::parseForFile);
            }else{
                connect(thread,&QThread::started,worker,&WorkerProcess::parseForTotalSizeWorker);
            }

            connect(worker,&WorkerProcess::finished,thread,&QThread::quit);
            connect(worker,&WorkerProcess::finished,worker,&WorkerProcess::deleteLater);
            connect(thread,&QThread::finished,thread,&QThread::deleteLater);
            thread->start();

            ui->fileNum->setChecked(false);
            ui->comboBox->setVisible(false);
        }
        break;
    default:
        QMessageBox::warning(nullptr,"HATA !","Hiçbir radyo butonu seçilmedi.\nYapılacak işleme göre radio button seçiniz.",QMessageBox::Ok);
        break;
    }

    ui->infoPacket->clear();
    ui->lineEdit->clear();
    this->destDirectory.clear();
    ui->label->clear();




    /*if (ui->radioButton->isChecked()) {
        if(this->destDirectory.isEmpty() || number <=0){
            QMessageBox::warning(nullptr,"HATA !","Hedef dizin seçilmedi veya\n0'dan büyük sayı giriniz..",QMessageBox::Ok);
        }else{
            this->packet->parseForPacketSize(this->destDirectory.toStdString(),number*1048576);
            delete this->packet;
            ui->infoPacket->clear();
            ui->lineEdit->clear();
            this->destDirectory.clear();
            ui->radioButton->setChecked(false);
        }
    } else if (ui->packetNum->isChecked()) {
        if(this->destDirectory.isEmpty() || number <=0){
            QMessageBox::warning(nullptr,"HATA !","Hedef dizin seçilmedi veya\n0'dan büyük sayı giriniz..",QMessageBox::Ok);
        }else{
            this->packet->parseForPacketCount(number,this->destDirectory.toStdString());
            delete this->packet;
            ui->lineEdit->clear();
            ui->infoPacket->clear();
            this->destDirectory.clear();
        }
    } else if (ui->fileNum->isChecked()) {
        if(this->destDirectory.isEmpty() || number <=0){
            QMessageBox::warning(nullptr,"HATA !","Hedef dizin seçilmedi veya\n0'dan büyük sayı giriniz..",QMessageBox::Ok);
        }else{
            this->packet->printPackets(this->destDirectory.toStdString(),number);
            delete this->packet;
            ui->infoPacket->clear();
            ui->lineEdit->clear();
            this->destDirectory.clear();
        }
    } else {
        QMessageBox::warning(nullptr,"HATA !","Hiçbir radyo butonu seçilmedi.\nYapılacak işleme göre radio button seçiniz.",QMessageBox::Ok);

    }*/



}

