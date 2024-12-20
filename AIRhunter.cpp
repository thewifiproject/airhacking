#include <QApplication>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QHBoxLayout>
#include <QTimer>
#include <QWidget>
#include <windows.h>
#include <wlanapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "wlanapi.lib")

struct WiFiNetwork {
    std::string bssid;
    std::string essid;
    int signalStrength;
    std::string encryption;
    int channel;
};

std::vector<WiFiNetwork> scanNetworks() {
    std::vector<WiFiNetwork> networks;

    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
    DWORD dwResult = 0;
    
    dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        std::cerr << "WlanOpenHandle failed." << std::endl;
        return networks;
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        std::cerr << "WlanEnumInterfaces failed." << std::endl;
        WlanCloseHandle(hClient, NULL);
        return networks;
    }

    for (int i = 0; i < (int)pIfList->dwNumberOfItems; ++i) {
        PWLAN_INTERFACE_INFO pIfInfo = &pIfList->InterfaceInfo[i];

        PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
        dwResult = WlanGetAvailableNetworkList(hClient, &pIfInfo->InterfaceGuid, 0, NULL, &pBssList);
        if (dwResult != ERROR_SUCCESS) {
            std::cerr << "WlanGetAvailableNetworkList failed." << std::endl;
            continue;
        }

        for (int j = 0; j < (int)pBssList->dwNumberOfItems; ++j) {
            PWLAN_AVAILABLE_NETWORK pBssEntry = &pBssList->Network[j];

            WiFiNetwork network;

            char ssid[33] = {0};
            memcpy(ssid, pBssEntry->dot11Ssid.ucSSID, pBssEntry->dot11Ssid.uSSIDLength);
            network.essid = ssid;
            
            network.signalStrength = (int)pBssEntry->wlanSignalQuality;
            network.encryption = pBssEntry->bSecurityEnabled ? "Secured" : "Open";
            
            networks.push_back(network);
        }

        if (pBssList) {
            WlanFreeMemory(pBssList);
        }
    }

    if (pIfList) {
        WlanFreeMemory(pIfList);
    }
    WlanCloseHandle(hClient, NULL);

    return networks;
}

class WiFiAnalyzer : public QWidget {
    Q_OBJECT

public:
    WiFiAnalyzer(QWidget *parent = nullptr) : QWidget(parent), timer(new QTimer(this)) {
        table = new QTableWidget(this);
        table->setColumnCount(5);
        table->setHorizontalHeaderLabels({"BSSID", "ESSID", "Signal Strength", "Encryption", "Channel"});
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

        startButton = new QPushButton("Start Capture", this);
        stopButton = new QPushButton("Stop Capture", this);
        stopButton->setEnabled(false);

        QHBoxLayout *buttonLayout = new QHBoxLayout;
        buttonLayout->addWidget(startButton);
        buttonLayout->addWidget(stopButton);

        QVBoxLayout *layout = new QVBoxLayout;
        layout->addWidget(table);
        layout->addLayout(buttonLayout);
        setLayout(layout);

        connect(startButton, &QPushButton::clicked, this, &WiFiAnalyzer::startCapture);
        connect(stopButton, &QPushButton::clicked, this, &WiFiAnalyzer::stopCapture);
        connect(timer, &QTimer::timeout, this, &WiFiAnalyzer::updateTable);
    }

private slots:
    void startCapture() {
        startButton->setEnabled(false);
        stopButton->setEnabled(true);
        timer->start(2000); // Update every 2 seconds
        updateTable();
    }

    void stopCapture() {
        startButton->setEnabled(true);
        stopButton->setEnabled(false);
        timer->stop();
    }

    void updateTable() {
        auto networks = scanNetworks();

        table->setRowCount(0);
        for (const auto &network : networks) {
            int row = table->rowCount();
            table->insertRow(row);

            table->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(network.bssid)));
            table->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(network.essid)));
            table->setItem(row, 2, new QTableWidgetItem(QString::number(network.signalStrength)));
            table->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(network.encryption)));
            table->setItem(row, 4, new QTableWidgetItem(QString::number(network.channel)));
        }
    }

private:
    QTableWidget *table;
    QPushButton *startButton;
    QPushButton *stopButton;
    QTimer *timer;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    WiFiAnalyzer analyzer;
    analyzer.setWindowTitle("Wi-Fi Analyzer");
    analyzer.resize(800, 600);
    analyzer.show();

    return app.exec();
}
