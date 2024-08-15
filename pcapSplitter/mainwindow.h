#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QThread>

#include "readAndProcessPacket.h"
#include "WorkerProcess.h"

QT_BEGIN_NAMESPACE
namespace Ui { class mainwindow; }
QT_END_NAMESPACE

class mainwindow : public QMainWindow
{
    Q_OBJECT

public:
    mainwindow(QWidget *parent = nullptr);
    ~mainwindow();

private slots:
    void on_selectInput_clicked();

    void on_selectOutput_clicked();

    void on_radioButton_toggled(bool checked);

    void on_packetNum_toggled(bool checked);

    void on_fileNum_toggled(bool checked);

    void on_runParse_clicked();

private:
    Ui::mainwindow *ui;
    QString destDirectory;
    readAndProcessPacket *packet;
    qint64 size;
    qint32 fileNum;
    qint32 packetNum;

    int control ;
    QString pcapFile;



};
#endif // MAINWINDOW_H
