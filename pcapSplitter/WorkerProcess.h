#ifndef WORKERPROCESS_H
#define WORKERPROCESS_H

#include <QObject>
#include <string>
#include <iostream>
#include <QString>

#include "readAndProcessPacket.h"
#include "ui_mainwindow.h"

class WorkerProcess : public QObject
{
    Q_OBJECT
public:
    WorkerProcess(std::string fName);
    ~WorkerProcess();
    void setCPram(int control);
    void setDestDirec(std::string director);
    QString setTxt;


public slots:
    void updateInfoText();
    void parseForSizeWorker();
    void parseForPacketCountWorker();
    void parseForFile();
    void parseForTotalSizeWorker();


signals:
    void finished();
    void readFinished();

private:
    //Ui::mainwindow *u ;
    std::string fileName ;
    readAndProcessPacket *packet;

    int cParam;
    std::string destDirec;
};

#endif // WORKERPROCESS_H
