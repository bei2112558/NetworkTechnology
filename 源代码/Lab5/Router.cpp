#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>    
#include <string>      
#include <stdio.h>     
#include <time.h>
#include <Winsock2.h>
#include <sstream>
#include <Windows.h>
#include <vector>
#include "pcap.h"   //���pca.h�����ļ�
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
using namespace std;

//������ر��ĸ�ʽ��IP����֡��ARP����֡����ͬ���͵�ICMP����֡
#pragma pack(1) // �ֽڶ���

typedef struct FrameHeader_t {  //����֡�ײ���14B
    BYTE DesMac[6]; //Ŀ�ĵ�ַ
    BYTE SrcMac[6]; //Դ��ַ
    WORD FrameType; //֡����
}FrameHeader_t;

typedef struct IPHeader_t {   // IP�ײ���20B
    BYTE Ver_HLen;  // �汾���ײ���ͷ���� ���ֱ�ռ4����
    BYTE Tos; //��������
    WORD TotalLen;  //�ܳ���
    WORD ID;   //��ʶ
    WORD Flag_Segment; //��־
    BYTE TTL;     //�������ڣ�ÿ����һ��ת���ͼ�1
    BYTE Protocol;   //Э��
    WORD Checksum;  //ͷ��У��ͣ����IP�ײ���У���
    ULONG SrcIP;   //ԴIP��ַ
    ULONG DstIP;   //Ŀ��IP��ַ
} IPHeader_t;

typedef struct ARPFrame_t {  //ARP֡
    FrameHeader_t FrameHeader;
    WORD HardwareType;//Ӳ�����ͣ���̫���ӿ�����Ϊ1
    WORD ProtocolType;//Э�����ͣ�IP����Ϊ0800H
    BYTE HLen;//Ӳ����ַ���ȣ������ַMAC����Ϊ6B
    BYTE PLen;//Э���ַ���ȣ�IP��ַ����Ϊ4B
    WORD Operation;//�������ͣ�ARP������Ϊ1����Ӧ����Ϊ2
    BYTE SendHa[6];//���ͷ�MAC��ַ
    DWORD SendIP;//���ͷ�IP��ַ
    BYTE RecvHa[6];//���շ�MAC��ַ
    DWORD RecvIP;//���շ�IP��ַ
} ARPFrame_t;

typedef struct IPFrame_t {  // ����֡�ײ���IP�ײ���IP���ݰ�
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
} IPFrame_t;

typedef struct ICMPData_t {   //ICMP ������Ӧ�����ģ�ͷ��8�ֽ�+��ѡ����
    BYTE Type; //����
    BYTE Code;  //���룬�������ֶ�һ���ʶICMP���ĵ���ϸ����
    WORD Checksum;  //У��ͣ��������ICMPͷ���Ϳ�ѡ���ݲ��ֵ�У�飨������IP�ײ���
    WORD Id; //��ʶ��
    WORD Seq;  //���
    BYTE Data[32];  //ѡ������
} ICMPData_t;

typedef struct ICMPFrame_t { //����֡�ײ���IP�ײ���ICMP������Ӧ������
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
    ICMPData_t ICMPData;
} ICMPFrame_t;

#pragma pack() // �ָ�Ĭ�϶��뷽ʽ

class PacketList;

class Packet {  //���屨���࣬ICMP������Ӧ������
private:
    ICMPFrame_t* icmpPkt;
    time_t time;  //����һ����ʱ������¼��������ʱ�䣬�����ж��Ƿ�ʱ������ʱ��
    bool discardState;  //�����Ƴ�״̬�����ڱ�ʾ��ת���������Ƿ���
    Packet* prev;  
    Packet* next;
public:
    Packet(ICMPFrame_t* ipPkt, time_t time);
    ~Packet() {};
    ICMPFrame_t* getICMPPkt() const { return icmpPkt; };
    time_t getTime() const { return time; };
    bool ifDiscard() const { return discardState; };  //�ж��Ƿ���
    void setDiscardState(bool discardState) { this->discardState = discardState; };
    Packet* getNext() { return next; };

    friend class PacketList;
};

class PacketList {  //���������࣬˫������
private:
    Packet* head;  //ͷ�ڵ�
    Packet* tail; //β��
    u_int size; //��������
public:
    PacketList();
    ~PacketList();
    void addBefore(ICMPFrame_t* icmpPkt);  //������ͷ�����뱨�ģ��ȴ�ת��
    Packet* Delete(Packet* packet);  //ɾ��ָ����
    Packet* getHead() const { return head; };
    u_int getSize() const { return size; };
};

class DeviceManager;

class Device {   //�����豸�࣬ÿ���豸������IP��ַ��һ��MAC��ַ
private:
    string name;    // �豸����
    string description; // �豸����
    DWORD ip[2];        // IP��ַ
    DWORD subnetMask[2];    // ��������
    BYTE mac[6];    // MAC��ַ

public:
    Device();
    ~Device();
    DWORD getIP(u_int idx = 0);
    DWORD getSubnetMask(u_int idx = 0);
    BYTE* getMac();
    string toStr();

    friend class DeviceManager;

};

class DeviceManager {  //�豸�����࣬�豸����
private:
    u_int deviceNum;  //�����豸��Ŀ
    Device* deviceList;  //�豸�б�����
    Device* openDevice;  //�򿪵������豸
    pcap_t* openHandle; //�򿪾��

public:
    DeviceManager();
    ~DeviceManager();
    u_int getDeviceNum() { return deviceNum; };
    Device* getOpenDevice() { return openDevice; };
    pcap_t* getOpenHandle() { return openHandle; };
    string toStr();
    void selectOpenDevice();         // ������������,ѡ���������򿪣���ô��������
    void setMac(BYTE* mac, Device* device);   // ����ָ�������豸��MAC��ַ
    DWORD findInterfaceIP(DWORD ip);    // ����IP��ַ���鿴�ʹ������Ƿ���ͬһ���Σ����ض�Ӧ�Ľӿ�IP��ַ
};

class ARPTable;             // ARP��˫������洢

class ARPEntry {    //ARP����
private:
    DWORD ip;               // IP��ַ
    BYTE mac[6];            // MAC��ַ
    time_t time;            // ��ʱ������ΪARP��������ʱ�䣬�������ű���ϻ�ʱ����ӱ���ɾ��
    ARPEntry* prev;  //ǰָ��
    ARPEntry* next;  //��һ��ָ��
    friend class ARPTable;

public:
    ARPEntry(DWORD ip, BYTE* mac, time_t time);
    ~ARPEntry() {};
    BYTE* getMac();  //�õ����ű����MAC��ַ
    string toStr(bool showAttr = true);
};

class ARPTable {   //ARP��
private:
    ARPEntry* head;  //ͷ��
    ARPEntry* tail; //β��
    u_int size;  //ARP�������
    u_int agingTime;  //ARP����ϻ�ʱ��

public:
    ARPTable();
    ~ARPTable();
    void add(DWORD ip, BYTE* mac); //���ARP�����������β��
    void Delete(ARPEntry* arpEntry);  //ɾ��ָ��ARP����
    ARPEntry* lookup(DWORD ip);  //Ѱ��ָ��IP��ARP����Ӷ���ȡMAC��ַ
    bool isExpired(ARPEntry* arpEntry) ;  //�ж�ARP�����Ƿ�ʱ�����ű���ʱ��>ARP���ϻ�ʱ��
    string toStr();
};

class RoutingTable;

class RoutingEntry {  //·�ɱ���
private:
    DWORD dest;         // Ŀ������
    DWORD netmask;      // ��������
    DWORD gateway;           // ���ص�ַ����һ����IP��ַ
    DWORD interfaceIP;          // ת��·�ɽӿڵ�IP��ַ
    RoutingEntry* prev;
    RoutingEntry* next;

    friend class RoutingTable;

public:
    RoutingEntry(DWORD dest, DWORD netmask, DWORD gateway, DWORD interfaceIP);
    ~RoutingEntry() {};
    DWORD getGateway() { return this->gateway; };
    string toStr(bool showAttr = true);
};

class RoutingTable {  //·�ɱ�˫������
private:
    Device* openDevice;  //�򿪵��豸ָ�룬��ʾ���豸��·�ɱ�
    RoutingEntry* head;
    RoutingEntry* tail;
    u_int size;  //·�ɱ���ĸ���

public:
    RoutingTable(Device* openDevice);
    ~RoutingTable();
    void add(DWORD dest, DWORD netmask, DWORD gateway);  //���·�ɱ��ÿ����Ӷ�����·�ɱ�ĩβ
    void add(const char* dest, const char* netmask, const char* gateway);
    void Delete(RoutingEntry* routingEntry);  //ɾ��ָ��·�ɱ���
    RoutingEntry* lookup(DWORD dest);  //����Ŀ��IP��Ӧ��·�ɱ����һ�����ƥ��ԭ��ÿ�β��Ҵ�ͷ��ʼ����
    RoutingEntry* lookup(char* dest);
    string toStr();
};

class Router {  //·��������
private:
    DeviceManager* deviceManager;  //·�����豸
    ARPTable* arpTable;  //��·������ARP��
    RoutingTable* routingTable;  //��·������·�ɱ�
    PacketList* packetBuf;  //ת����������
    u_int pktLifetime;  //ÿ�����ڻ������е�����ʱ�䣬��ʱ����
    HANDLE hFwdThrd;  //ת���߳�
    HANDLE hRcvThrd;  //�����߳�
    CRITICAL_SECTION cs;  //������Դ�ٽ���
public:
    Router();
    ~Router();
    DeviceManager* getDeviceManager() { return deviceManager; };
    ARPTable* getARPTable() { return arpTable; };
    RoutingTable* getRoutingTable() { return routingTable; };
    PacketList* getPacketBuf() { return packetBuf; };
    u_int getPktLifetime() { return pktLifetime; };
    CRITICAL_SECTION& getCS() { return cs; };

    BYTE* getOpenDeviceMac(Device* device);         // ��ȡIP��ַ��MAC��ַӳ�䣬���APR����û�У���㲥ARP��ȡ
    void cmdInput();                                 // ���߳�������·���������ָ��
    bool sendARPReqest(DWORD ip);                   // �㲥ARP���󣬻��ָ���豸IP��Ӧ��MAC��ַ
    void forward(ICMPFrame_t* pkt, BYTE* dstMac);   // ת��ICMP���ݰ���ָ��Ŀ��IP
    void tryToFwd(Packet* pkt);       // ���Ե���forward����ת��ICMP���ݰ�����ת���̵߳���
    static DWORD WINAPI fwdThrd(LPVOID lpParam);    // ת���̺߳���
    static DWORD WINAPI rcvThrd(LPVOID lpParam);    // �����̺߳���
};

//һЩ��������
string IPToString(DWORD addr) {
    char addrStr[16] = { 0 };
    sprintf(addrStr, "%d.%d.%d.%d", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
    return string(addrStr);
}

string MacToString(BYTE* mac) {
    char macStr[18] = { 0 };
    sprintf(macStr, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(macStr);
}

string intToString(int value) {
    char valueStr[10] = { 0 };
    sprintf(valueStr, "%d", value);
    return string(valueStr);
}

string u_intToString(u_int value) {
    char valueStr[10] = { 0 };
    sprintf(valueStr, "%d", value);
    return string(valueStr);
}

string timeToString(time_t time) {
    char timeStr[20] = { 0 };
    strftime(timeStr, 20, "%H:%M:%S", localtime(&time));
    return string(timeStr);
}

bool macCmp(BYTE* mac1, BYTE* mac2) { //�ж�����MAC��ַ�Ƿ���ͬ
    if (mac2 == NULL) {
        return memcmp(mac1, "\0\0\0\0\0\0", 6) == 0;
    }
    else {
        return memcmp(mac1, mac2, 6) == 0;
    }
}

string recvLog(DWORD srcIP, BYTE* srcMac, DWORD dstIP, BYTE* dstMac, int ttl) {  //������־���
    string str = "";
    string temp;
    str += "��INF�� Packet Received: \nSrcIP           SrcMac            DstIP           DstMac            TTL\n";
    temp = IPToString(srcIP); temp.resize(16, ' '); str += temp;
    temp = MacToString(srcMac); temp.resize(18, ' '); str += temp;
    temp = IPToString(dstIP); temp.resize(16, ' '); str += temp;
    temp = MacToString(dstMac); temp.resize(18, ' '); str += temp;
    temp = intToString(ttl); str += temp;
    return str;
}

string fwrdLog(DWORD dstIP, BYTE* dstMac, int ttl, bool nextHop=true) { //ת����־���
    string str = "";
    string temp;
    if (nextHop) {
        str += "��INF�� Packet Forwarded: \nNextHop         DstMac            TTL\n";
    }
    else {
        str += "��INF�� Packet Forwarded: \nDstIP           DstMac            TTL\n";
    }
    temp = IPToString(dstIP); temp.resize(16, ' '); str += temp;
    temp = MacToString(dstMac); temp.resize(18, ' '); str += temp;
    temp = intToString(ttl); str += temp;
    return str;
}

ARPFrame_t* makeARPRequestPkt(u_char* dstMac, u_char* srcMac,DWORD dstIP, DWORD srcIP) { //��װARP������
    ARPFrame_t* ARPFrame = new ARPFrame_t;
    memcpy(ARPFrame->FrameHeader.DesMac, dstMac, 6);
    memcpy(ARPFrame->FrameHeader.SrcMac, srcMac, 6);
    ARPFrame->FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
    ARPFrame->HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
    ARPFrame->ProtocolType = htons(0x0800);//Э������ΪIP
    ARPFrame->HLen = 6;//Ӳ����ַ����Ϊ6
    ARPFrame->PLen = 4; // Э���ַ��Ϊ4
    ARPFrame->Operation = htons(0x0001);//����ΪARP����
    memcpy(ARPFrame->SendHa, srcMac, 6);
    ARPFrame->SendIP = srcIP;
    memcpy(ARPFrame->RecvHa, dstMac, 6);
    ARPFrame->RecvIP = dstIP;
    return ARPFrame;
}

bool isARPPkt(const u_char* pktData) {
    return ntohs(((ARPFrame_t*)pktData)->FrameHeader.FrameType) == 0x0806;
}

bool isIPPkt(const u_char* pktData) {
    return ntohs(((ARPFrame_t*)pktData)->FrameHeader.FrameType) == 0x0800;
}

u_short addIPPktCheckSum(u_short* pkt_data, int len) {  //����IP�ײ���У��ͣ���������̫��֡�ײ���,lenΪ��̫��֡�ײ�+IPͷ
    u_long sum;
    u_short basic;
    u_short* pointer;
    sum = 0;
    basic = ((IPFrame_t*)pkt_data)->IPHeader.Checksum;  //ԭ����У���
    pointer = pkt_data;  //ԭ���ı���ָ��λ��
    ((IPFrame_t*)pkt_data)->IPHeader.Checksum = 0;  //У��͸���Ϊ0
    pkt_data = (u_short*)&(((IPFrame_t*)pkt_data)->IPHeader);  //��ȡIP�ײ�
    len -= sizeof(FrameHeader_t); //��ȥ��̫��֡�ײ�
    while (len > 1) {  //16����Ϊ��λ
        sum += *pkt_data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char*)pkt_data;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    pkt_data = pointer;
    ((IPFrame_t*)pkt_data)->IPHeader.Checksum = basic;
    return (u_short)(~sum);  //У���ȡ��
}

u_short addICMPChecksum(u_short* pkt_data, int len) {  //����ICMP���ĵ�У��ͣ�ICMPͷ��+ICMP���ݣ�������IP�ײ�
    u_long sum;
    u_short basic;
    u_short* pointer;
    sum = 0;
    basic = ((ICMPFrame_t*)pkt_data)->ICMPData.Checksum;
    pointer = pkt_data;
    ((ICMPFrame_t*)pkt_data)->ICMPData.Checksum = 0;
    pkt_data = (u_short*)&((ICMPFrame_t*)pkt_data)->ICMPData; //��λ��ICMPͷ��λ��
    len -= (sizeof(FrameHeader_t)+sizeof(IPHeader_t)); //���ȼ�ȥ��̫��֡�ײ���IP�ײ�
    while (len > 1) {
        sum += *pkt_data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char*)pkt_data;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    pkt_data = pointer;
    ((ICMPFrame_t*)pkt_data)->ICMPData.Checksum = basic;
    return (u_short)(~sum);
}

bool ifICMPCheckSum(u_short* pkt_data, int len) {  //�ж�ICMP����У��ͣ��Ƿ����
    u_long sum;
    sum = 0;
    pkt_data = (u_short*)&((ICMPFrame_t*)pkt_data)->ICMPData;
    len -= (sizeof(FrameHeader_t) + sizeof(IPHeader_t)); //���ȼ�ȥ��̫��֡�ײ���IP�ײ�
    while (len > 1) {
        sum += *pkt_data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char*)pkt_data;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    if (sum != 0xffff) {  //�������ȫ1��У��ʹ���
        cout << "��ERR�� ICMP checksum error" << endl;
    }
    return sum != 0xffff;
}

void setICMPChecksum(u_short* pktData) {
    ((IPFrame_t*)pktData)->IPHeader.Checksum = addIPPktCheckSum(pktData, sizeof(IPFrame_t));
    ((ICMPFrame_t*)pktData)->ICMPData.Checksum = addICMPChecksum(pktData, sizeof(ICMPFrame_t));
}

Packet::Packet(ICMPFrame_t* icmpPingPkt, time_t time) {
    this->icmpPkt = icmpPingPkt;
    this->time = time;
    this->discardState = false;
    next = NULL;
    prev = NULL;
}

PacketList::PacketList() {
    head = NULL;
    tail = NULL;
    size = 0;
}

PacketList::~PacketList() {
    Packet* p = head;
    while (p != NULL) {
        Packet* tmp = p;
        p = p->next;
        delete tmp;
    }
}

void PacketList::addBefore(ICMPFrame_t* icmpPingPkt) {
    Packet* pkt = new Packet(icmpPingPkt, time(NULL));
    if (head == NULL) {
        head = pkt;
        tail = pkt;
    }
    else {
        pkt->next = head;
        head->prev = pkt;
        head = pkt;
    }
    size++;
}

Packet* PacketList::Delete(Packet* packet) {
    Packet* ret;
    ret = packet->next;
    if (packet == head) {
        head = packet->next;
        if (head != NULL) {
            head->prev = NULL;
        }
    }
    else if (packet == tail) {
        tail = packet->prev;
        if (tail != NULL) {
            tail->next = NULL;
        }
    }
    else {
        packet->prev->next = packet->next;
        packet->next->prev = packet->prev;
    }
    delete packet;
    size--;
    return ret;
}

Device::Device() {
    name = "";
    description = "";
    ip[0] = 0;
    ip[1] = 0;
    subnetMask[0] = 0;
    subnetMask[1] = 0;
    memset(mac, 0, 6);
}

Device::~Device() {}

DWORD Device::getIP(u_int idx) {
    if (idx < 2) {
        if (subnetMask[idx] == DWORD(0)) {
            cout << "��ERR�� Get IP Error: subnetMask[" << idx << "] is not set." << endl;
        }
    }
    else {
        cout << "��ERR�� Get IP Error: idx out of range." << endl;
        exit(1);
    }
    return ip[idx];
}

DWORD Device::getSubnetMask(u_int idx) {
    if (idx < 2) {
        if (subnetMask[idx] == 0) {
            cout << "��ERR�� Get Subnet Mask Error: subnetMask[" << idx << "] is not set." << endl;
        }
    }
    else {
        cout << "��ERR�� Get Subnet Mask Error: idx: " << idx << " out of range." << endl;
        exit(1);
    }
    return subnetMask[idx];
}

BYTE* Device::getMac() {
    BYTE temp[6];
    memset(temp, 0, 6);
    if (memcmp(mac, temp, 6) == 0) {
        cout << "��ERR�� Get MAC Error: mac is not set." << endl;
        return NULL;
    }
    return mac;
}

string Device::toStr() {
    string str = "";
    str += "Name: " + name + "\nDescription: " + description;
    if (subnetMask[0] != 0) {
        if (subnetMask[1] != 0) {
            str += "\nIP Addr1: " + IPToString(ip[0]) + "\tSubnet Mask: " + IPToString(subnetMask[0])
                + "\nIP Addr2: " + IPToString(ip[1]) + "\tSubnet Mask: " + IPToString(subnetMask[1]);
        }
        else {
            str += "\nIP Addr: " + IPToString(ip[0]) + "\tSubnet Mask: " + IPToString(subnetMask[0]);
        }
    }
    if (memcmp(mac, "\0\0\0\0\0\0", 6) != 0) {
        str += "\nMAC Addr: " + MacToString(mac);
    }
    return str;
}

DeviceManager::DeviceManager() {
    deviceNum = 0;
    deviceList = NULL;
    openDevice = NULL;
    openHandle = NULL;
}

DeviceManager::~DeviceManager() {
    if (deviceList != NULL) {
        delete[] deviceList;
    }
}

string DeviceManager::toStr() {
    string str = "";
    u_int i;
    if (deviceNum == 0) {
        str += "No device";
    }
    else {
        str += "Device Num: " + u_intToString(deviceNum) + "\n";
        for (i = 0; i < deviceNum; i++) {
            str += "Device " + u_intToString(u_int(i + 1)) + ":\n" + deviceList[i].toStr() + "\n";
        }
    }
    return str;
}

void DeviceManager::selectOpenDevice() {
    pcap_if_t* alldevs; //ָ���豸�����ײ���ָ��
    pcap_if_t* d;
    pcap_addr_t* a;
    char errbuf[PCAP_ERRBUF_SIZE];  //������Ϣ������

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {  // ��ȡ���������б�,
        cout << "��ERR�� Error in pcap_findalldevs: " << errbuf << endl; //��ȡ����ӿ��б�ʧ�ܣ���������
        exit(1);
    }
    for (d = alldevs; d != NULL; d = d->next) { // ��ȡ�豸����
        deviceNum++;
    }
    if (deviceNum == 0) { //����ӿ��豸Ϊ0
        cout << "��ERR�� No device found! Make sure WinPcap is installed." << endl;
        exit(1);
    }
    deviceList = new Device[deviceNum];
    int i = 0;
    for (d = alldevs; d != NULL; d = d->next) { //�����豸������ȡ�豸��������
        deviceList[i].name = string(d->name);
        deviceList[i].description = string(d->description);
        int j;
        for (j = 0, a = d->addresses; j < 2 && a != NULL; a = a->next) {    // ��ȡ�豸������IP��ַ
            if (a->addr->sa_family == AF_INET) {//�жϸõ�ַ�Ƿ�ΪIP��ַ
                char address[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)a->addr)->sin_addr), address, sizeof(address));
                deviceList[i].ip[j] = inet_addr(address);
                inet_ntop(AF_INET, &(((struct sockaddr_in*)a->netmask)->sin_addr), address, sizeof(address));
                deviceList[i].subnetMask[j] = inet_addr(address);
                j++;
            }
        }
        i++;
    }
    pcap_freealldevs(alldevs);
    cout << "��SUC�� Find Devices Success! Devices�� " << endl;
    cout << toStr() << endl;
    //ѡ�������豸����
    u_int id;
    cout << "��CMD�� Please input the device index: ";
    cin >> id;  //����Ҫ�򿪵������豸
    if (id < 1 || id > deviceNum) {
        cout << "��ERR�� Invalid device index" << endl;
        exit(1);
    }
    id--;
    openDevice = &deviceList[id];  //��ô򿪵������豸
    if ((openHandle = pcap_open(openDevice->name.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) ==NULL) { // ������
        cout << "��ERR�� Error in pcap_open_live: " << errbuf << endl;
        exit(1);
    }
   if (pcap_datalink(openHandle) != DLT_EN10MB) { // �ж������Ƿ�Ϊ��̫������
        cout << "��ERR�� This device is not an Ethernet" << endl;
        exit(1);
    }
    if (pcap_setnonblock(openHandle, 1, errbuf) == -1) { // ��������Ϊ������ģʽ
        cout << "��ERR�� Error in pcap_setnonblock: " << errbuf << endl;
        exit(1);
    }
    cout << "��SUC�� Device opened successfully" << endl;
}

void DeviceManager::setMac(BYTE* mac, Device* device) {
    if (mac == NULL) {
        cout << "��ERR�� Set MAC Error: mac is NULL." << endl;
        return;
    }
    if (device == NULL) {
        cout << "��ERR�� Set MAC Error: device is NULL." << endl;
    }
    if (device->getMac() != NULL) {
        cout << "��ERR�� Set MAC Error: mac is already set." << endl;
        return;
    }
    memcpy(device->mac, mac, 6);
}

DWORD DeviceManager::findInterfaceIP(DWORD ip) {
    if (openDevice == NULL) {
        cout << "��ERR�� Find Itf Error: openDevice is NULL." << endl;
        return 0;
    }
    if (openHandle == NULL) {
        cout << "��ERR�� Find Itf Error: openHandle is NULL." << endl;
        return 0;
    }
    if ((ip & openDevice->subnetMask[0]) == (openDevice->ip[0] & openDevice->subnetMask[0])) {
        return openDevice->ip[0];  //�ͽӿ�0�������ͬ��ip��ַ �߼��� ����
    }
    if ((ip & openDevice->subnetMask[1]) == (openDevice->ip[1] & openDevice->subnetMask[1])) {
        return openDevice->ip[1];  //�ͽӿ�1�������ͬ
    }
    return 0;
}

ARPEntry::ARPEntry(DWORD ip, BYTE* mac, time_t time) {
    this->ip = ip;
    memcpy(this->mac, mac, 6);
    this->time = time;
    this->prev = NULL;
    this->next = NULL;
}

BYTE* ARPEntry::getMac() {
    if (memcmp(mac, "\0\0\0\0\0\0", 6) == 0) {
        cout << "��ERR�� Get MAC Error: mac is not set." << endl;
        return NULL;
    }
    return mac;
}

string ARPEntry::toStr(bool showAttr) {
    string str = "";
    string temp;
    if (showAttr) {  //���IP��ַ��MAC��ַ������ʱ��
        str += "IP Address      Mac Address       Time\n";
    } 
    temp = IPToString(ip); temp.resize(16, ' '); str += temp;
    temp = MacToString(mac); temp.resize(18, ' '); str += temp;
    temp = timeToString(time);  str += temp;
    return str;
}

ARPTable::ARPTable() {
    this->head = NULL;
    this->tail = NULL;
    this->size = 0;
    this->agingTime = 60;  //ARP����ϻ�ʱ������Ϊ60s
}

ARPTable::~ARPTable() {
    ARPEntry* arpEntry;
    arpEntry = head;
    while (arpEntry != NULL) {
        ARPEntry* next = arpEntry->next;
        delete arpEntry;
        arpEntry = next;
    }
}

void ARPTable::add(DWORD ip, BYTE* mac) {
    ARPEntry* arpEntry;
    if (lookup(ip) != NULL) { //ָ��IP��ARP�����Ѿ�����
        return;
    }
    arpEntry = new ARPEntry(ip, mac, time(NULL));  //������ű�����ӣ�������ʱ��
    cout << "��INF�� Add ARP Entry: " << arpEntry->toStr(false) << endl;
    if (head == NULL) {  //ͷָ��Ϊ0.����
        head = arpEntry;
        tail = arpEntry;
    }
    else {
        tail->next = arpEntry;
        arpEntry->prev = tail;
        tail = arpEntry;
    }
    size++;
}

void ARPTable::Delete(ARPEntry* arpEntry) {
    cout << "��INF�� Delete ARP Entry: " << arpEntry->toStr(false) << endl;
    if (arpEntry->prev == NULL) {
        head = arpEntry->next;
    }
    else {
        arpEntry->prev->next = arpEntry->next;
    }
    if (arpEntry->next == NULL) {
        tail = arpEntry->prev;
    }
    else {
        arpEntry->next->prev = arpEntry->prev;
    }
    delete arpEntry;
    size--;
}

ARPEntry* ARPTable::lookup(DWORD ip) {
    ARPEntry* arpEntry;
    arpEntry = head;
    while (arpEntry != NULL) {
        if (arpEntry->ip == ip) {  //�ҵ�IP��Ӧ��ARP����
            return arpEntry;
        }
        arpEntry = arpEntry->next;
    }
    return NULL;
}

bool ARPTable::isExpired(ARPEntry* arpEntry) {  //�Ƿ�ʱ
    return u_int(time(NULL) - arpEntry->time) > this->agingTime;
}

string ARPTable::toStr() {
    string str = "";
    ARPEntry* arpEntry;
    if (size == 0) {
        str += "ARP Table: None";
        return str;
    }
    str += "ARPTable: \nIP Address      Mac Address       Time\n";
    arpEntry = head;
    while (arpEntry != NULL) {
        str += arpEntry->toStr(false) + "\n";
        arpEntry = arpEntry->next;
    }
    return str;
}

RoutingEntry::RoutingEntry(DWORD dest, DWORD netmask, DWORD gateway, DWORD interfaceIP) {
    this->dest = dest;
    this->netmask = netmask;
    this->gateway = gateway;
    this->interfaceIP = interfaceIP;
    this->prev = NULL;
    this->next = NULL;
}

string RoutingEntry::toStr(bool showAttr) { //·�ɱ��������Ŀ������ ���� ����(��һ����ַ) �ӿ�(ת���ӿڵ�IP��ַ)
    string str = "";
    string temp;
    if (showAttr) {  
        str += "Destination     Netmask         Gateway         Interface\n";
    }         
    temp = IPToString(this->dest);  temp.resize(16, ' ');  str += temp;
    temp = IPToString(this->netmask);  temp.resize(16, ' ');  str += temp;
    temp = IPToString(this->gateway);  temp.resize(16, ' ');  str += temp;
    temp = IPToString(this->interfaceIP);  str += temp;
    return str;
}

RoutingTable::RoutingTable(Device* openDevice) {
    this->openDevice = openDevice;
    this->head = NULL;
    this->tail = NULL;
    this->size = 0;
}

RoutingTable::~RoutingTable() {
    RoutingEntry* routingEntry;
    routingEntry = this->head;
    while (routingEntry != NULL) {
        RoutingEntry* next = routingEntry->next;
        delete routingEntry;
        routingEntry = next;
    }
}

void RoutingTable::add(DWORD dest, DWORD netmask, DWORD gateway) {
    RoutingEntry* routingEntry;
    DWORD interfaceIP;
    //·�ɱ����Ѵ���
    if ((routingEntry = lookup(dest)) != NULL && (routingEntry->netmask != 0)) {
        return;
    }
    switch (netmask) {  //���ݸ�����gateway����IP�жϣ��Ƿ�����·�ɵ�ת���ӿڣ�����������жϣ�IP & ��������
    case 0:  //��������Ϊ0�����Ĭ��·��
        if ((openDevice->getIP(0) & openDevice->getSubnetMask(0)) == (gateway & openDevice->getSubnetMask(0))) {
            interfaceIP = openDevice->getIP(0);
        }
        else if ((openDevice->getIP(1) & openDevice->getSubnetMask(1)) == (gateway & openDevice->getSubnetMask(1))) {
            interfaceIP = openDevice->getIP(1);
        }
        else { //��������IP��ַ����·�ɵĽӿ�
            cout << "��ERR�� Add Routing Entry Error: default destination is unreachable" << endl;
            return;
        }
        routingEntry = new RoutingEntry(0, 0, gateway, interfaceIP); //Ĭ��·�ɣ�Ŀ����������붼Ϊ0
        break;
    default:  //�����ͨ·��
        if ((openDevice->getIP(0) & openDevice->getSubnetMask(0)) == (gateway & openDevice->getSubnetMask(0))) {
            interfaceIP = openDevice->getIP(0);
        }
        else if ((openDevice->getIP(1) & openDevice->getSubnetMask(1)) == (gateway & openDevice->getSubnetMask(1))) {
            interfaceIP = openDevice->getIP(1);
        }
        else {
            cout << "��ERR�� Add Routing Entry Error: No interface found for this destination." << endl;
            return;
        }
        routingEntry = new RoutingEntry(dest & netmask, netmask, gateway, interfaceIP); //�����ͨ·��
    }
    //���������β��
    if (head == NULL) {
        head = tail = routingEntry;
    }
    else {
        tail->next = routingEntry;
        routingEntry->prev = tail;
        tail = routingEntry;
    }
    size++;
    cout << "��INF�� Routing Entry Added�� " << routingEntry->toStr(false) << endl;
}

void RoutingTable::add(const char* dest, const char* netmask, const char* gw) {
    add(inet_addr(dest), inet_addr(netmask), inet_addr(gw));
}

void RoutingTable::Delete(RoutingEntry* routingEntry) {
    if (routingEntry == NULL) {
        cout << "��ERR�� Delete Routing Entry Error: Routing entry not found." << endl;
        return;
    }
    if (size == 0) {
        cout << "��ERR�� Delete Routing Entry Error: Routing table is empty." << endl;
        return;
    }
    cout << "��INF�� Delete Routing Entry: " << routingEntry->toStr(false) << endl;
    if (routingEntry->prev == NULL) {  //ǰָ��Ϊ��
        head = routingEntry->next;
    }
    else {
        routingEntry->prev->next = routingEntry->next;
    }
    if (routingEntry->next == NULL) {  //��ָ��Ϊ��
        tail = routingEntry->prev;
    }
    else {
        routingEntry->next->prev = routingEntry->prev;
    }
    delete routingEntry;
    size--;
}

RoutingEntry* RoutingTable::lookup(DWORD dest) {
    RoutingEntry* routingEntry;
    RoutingEntry* result;
    DWORD maxPrefixNetmask;  //�ƥ������

    routingEntry = head;
    if (routingEntry == NULL) {  //·�ɱ�Ϊ��
        cout << "��ERR�� Look up Routing Table Error: Routing table is empty." << endl;
        return NULL;
    }
    result = NULL;
    maxPrefixNetmask = head->netmask;
    while (routingEntry != NULL) {  //��ͷ����·�ɱ�����
        //�ж�������Ƿ���ȣ�Ŀ��IP & ����
        if ((routingEntry->dest & routingEntry->netmask) == (dest & routingEntry->netmask)) {  //��������
            if (ntohl(routingEntry->netmask) > ntohl(maxPrefixNetmask)) { //�ж����볤�ȣ��ƥ��
                maxPrefixNetmask = routingEntry->netmask; //���¸���������
                result = routingEntry;
            }
            //result = routingEntry;
        }
        routingEntry = routingEntry->next;
    }
    if (result == NULL) {  //û���ҵ�
        cout << "��ERR�� Look up Routing Table Error: Routing entry not found." << endl;
    }
    return result;
}
RoutingEntry* RoutingTable::lookup(char* dest){
    return lookup(inet_addr(dest));
}

string RoutingTable::toStr() {
    string str = "";
    RoutingEntry* routingEntry;

    routingEntry = head;
    if (routingEntry == NULL) {  
        str += "RoutingTable: None";
    }
    else {
        str += "RoutingTable: \nDestination     Netmask         Gateway         Interface\n";
        while (routingEntry != NULL) {
            str += routingEntry->toStr(false) + "\n";
            routingEntry = routingEntry->next;
        }
    }
    return str;
}

Router::Router() {
    deviceManager = new DeviceManager();
    deviceManager->selectOpenDevice();       //�������������豸��ѡ��򿪵�����
    getOpenDeviceMac(deviceManager->getOpenDevice()); // ��ȡ���豸��Mac��ַ

    packetBuf = new PacketList();
    pktLifetime = 10; // ���ݰ��ڻ�����������������ʱ��
    arpTable = new ARPTable();
    routingTable = new RoutingTable(deviceManager->getOpenDevice());
    routingTable->add("0.0.0.0", "0.0.0.0", "206.1.2.2");   // ���Ĭ��·�ɣ�����ɾ�������޸�

    InitializeCriticalSection(&cs);
    hFwdThrd = CreateThread(NULL, 0, fwdThrd, this, 0, NULL); // ����ת���߳�
    Sleep(100);
    hRcvThrd = CreateThread(NULL, 0, rcvThrd, this, 0, NULL); // ���������߳�
    Sleep(100);
    cmdInput();     // ���߳̽�����������ָ��
}

Router::~Router() {
    delete deviceManager;
    delete arpTable;
    delete routingTable;
    CloseHandle(hRcvThrd);
    CloseHandle(hFwdThrd);
    DeleteCriticalSection(&cs);
}

BYTE* Router::getOpenDeviceMac(Device* device) { // ʹ��ARPЭ���ȡָ�������豸��MAC��ַ
    BYTE RecvHa[6];
    BYTE SendHa[6];
    DWORD RevIP;
    DWORD SendIP;
    ARPFrame_t* ARPFrame;  //ARP�����
    ARPFrame_t* captureARPPkt; //���񵽵�ARP��Ӧ��
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;

    if (device == NULL) {
        cout << "��ERR�� Get Open Device Error: No device opened!" << endl;
        return NULL;
    }
    if (device->getMac() != NULL) { // ����Ѿ���ȡ��MAC��ַ��ֱ�ӷ��أ�����ͨ��ARPЭ���ȡ
        return device->getMac();
    }

    memset(RecvHa, 0xff, 6);                            // Ŀ��MAC��ַΪ�㲥��ַ
    memset(SendHa, 0x66, 6);                            // ԴMAC��ַΪ��ٵ�66-66-66-66-66-66
    RevIP = deviceManager->getOpenDevice()->getIP(0);            // Ŀ��IP��ַΪ����IP��ַ
    SendIP = inet_addr("112.112.112.112");                        // α��ԴIP��ַ
    ARPFrame = makeARPRequestPkt(RecvHa, SendHa, SendIP, RevIP);     // �鹹��ַ��ARP�������ݰ�

    //ģ��Զ��������ARP���󣬲��񱾻���ARP��Ӧ����ȡ��������ӿ�MAC��ַ
    if (pcap_sendpacket(deviceManager->getOpenHandle(), (u_char*)ARPFrame, sizeof(ARPFrame_t)) != 0) {
        cout << "��ERR�� Get Open Device Error: Error in pcap_sendpacket: " << pcap_geterr(deviceManager->getOpenHandle()) << endl;
        exit(1);
    }
    while (true) {
        int result = pcap_next_ex(deviceManager->getOpenHandle(), &pkt_header, &pkt_data); //�õ�pcap_next_ex�ķ��ؽ��
        if (result == 0) {  //δ�������ݰ�
            continue;
        }
        else if (result == -1) {  //���ù��̷�������
            cout << "��ERR�� Get Open Device Error: Error in reading the packets: " << pcap_geterr(deviceManager->getOpenHandle()) << endl;
            exit(-1);
        }
        else {  //result=1������ɹ�
            captureARPPkt = (ARPFrame_t*)pkt_data;  //���񵽵����ݰ�ת��Ϊ�Զ����ARPFrame_t���ݰ�����
            //�жϲ����IP���Ƿ�Ϊ֮ǰ����ARP�������Ӧ��
            if (ntohs(captureARPPkt->FrameHeader.FrameType) == 0x0806 && ntohs(captureARPPkt->Operation) == 0x0002 && captureARPPkt->RecvIP == SendIP && captureARPPkt->SendIP == RevIP) {
                cout << "��INF�� ARP Reply To Open Device Received" << endl;
                deviceManager->setMac(captureARPPkt->FrameHeader.SrcMac, device);  //����MAC��ַ
                break;
            }
        }
    }
    cout << "��SUC�� Get IP-MAC map successfully. Open device info :" << endl;
    cout << deviceManager->getOpenDevice()->toStr() << endl;
    return device->getMac();
}

void Router::cmdInput() {
    cout << "=========================================================\n";
    cout << "��CMD��Command Thread started. Cmds listed bellow\n";
    cout << "---------------------------------------------------------\n";
    cout << "ROUTING_TABLE:\n";
    cout << "route    add [destination] mask [subnetMast] [gateway]\n";
    cout << "route delete [destination]\n";
    cout << "route  print\n";
    cout << "---------------------------------------------------------\n";
    cout << "ARP_TABLE:\n";
    cout << "arp -a\n";
    cout << "=========================================================\n";
    char cmd[50];
    cin.ignore();
    while (true) {
        cout << "��CMD�� Please input command: ";
        cin.getline(cmd, 50);  //����ָ��

        char* p;
        vector<string> cmdVec;
        if (string(cmd) == "") {
            cout << "��CMD�� Command empty!" << endl;
            return;
        }
        p = strtok(cmd, " ");
        do {
            cmdVec.push_back(string(p));
        } while ((p = strtok(NULL, " ")) != NULL);
        if (cmdVec[0] == "route") {
            if (cmdVec[1] == "add") {
                routingTable->add(cmdVec[2].c_str(), cmdVec[4].c_str(), cmdVec[5].c_str());
            }
            if (cmdVec[1] == "delete") {
                if (cmdVec[2] == "0.0.0.0") {
                    cout << "��ERR�� Cannot delete default route!" << endl;
                    return;
                }
                routingTable->Delete(routingTable->lookup(inet_addr(cmdVec[2].c_str())));
            }
            if (cmdVec[1] == "change") {
                routingTable->Delete(routingTable->lookup(inet_addr(cmdVec[2].c_str())));
                routingTable->add(cmdVec[2].c_str(), cmdVec[4].c_str(), cmdVec[5].c_str());
            }
            if (cmdVec[1] == "print") {
                cout << routingTable->toStr() << endl;
            }
        }
        if (cmdVec[0] == "arp") {
            if (cmdVec[1] == "-a") {
                cout << arpTable->toStr() << endl;
            }
        }
    }
}

bool Router::sendARPReqest(DWORD ip) {
    BYTE dstMac[6];
    BYTE srcMac[6];
    DWORD dstIP;
    DWORD srcIP;
    ARPFrame_t* ARPFrame; //�㲥ARP������

    if (ip == 0) {
        cout << "��ERR�� bcstARPReq Error: dest ip is NULL" << endl;
        return false;
    }
    if (deviceManager->getOpenDevice() == NULL) {
        cout << "��ERR�� bcstARPReq Error: openDevice is NULL" << endl;
        return false;
    }
    if ((srcIP = deviceManager->findInterfaceIP(ip)) == 0) {
        cout << "��ERR�� bcstARPReq Error: ip is not destined locally" << endl;
        return false;
    }
    memset(dstMac, 0xff, 6);  //Ŀ��MAC��ַΪ�㲥��ַ
    memcpy(srcMac, deviceManager->getOpenDevice()->getMac(), 6);  //Դ��ַΪ���豸�Ľӿ�MAC��ַ
    dstIP = ip;
    ARPFrame = makeARPRequestPkt(dstMac, srcMac, srcIP, dstIP); //��װARP������
    //�㲥ARP����
    if (pcap_sendpacket(deviceManager->getOpenHandle(), (u_char*)ARPFrame, sizeof(ARPFrame_t)) != 0) {
        cout << "��ERR�� bcstARPReq Error: Error in pcap_sendpacket: " << pcap_geterr(deviceManager->getOpenHandle()) << endl;
        return false;
    }
    return true;
}

void Router::forward(ICMPFrame_t* pkt, BYTE* dstMac) {
    if (pkt == NULL) {
        cout << "��ERR�� Fwd Pkt Error: Invalid packet!" << endl;
        return;
    }
    if (dstMac == NULL) {
        cout << "��ERR�� Fwd Pkt Error: Invalid destination MAC address!" << endl;
        return;
    }
    memcpy(pkt->FrameHeader.SrcMac, deviceManager->getOpenDevice()->getMac(), 6);
    memcpy(pkt->FrameHeader.DesMac, dstMac, 6);
    pkt->IPHeader.TTL--;  //ÿת��һ�Σ�����ʱ���1
    setICMPChecksum((u_short*)pkt);  //���¼���У���
    if (pcap_sendpacket(deviceManager->getOpenHandle(), (u_char*)pkt, sizeof(ICMPFrame_t)) != 0) {
        cout << "��ERR�� Fwd Pkt Error: Error in pcap_sendpacket: " << pcap_geterr(deviceManager->getOpenHandle()) << endl;
        exit(1);
    }
}

void Router::tryToFwd(Packet* pkt) {
    if (pkt == NULL) {
        cout << "��ERR�� tryToFwd Error: pkt is NULL" << endl;
        return;
    }
    BYTE* dstMac;
    RoutingEntry* routingEntry;
    ARPEntry* arpEntry;

    if (pkt->ifDiscard()) {  //�жϰ��Ƴ�״̬���Ƿ���Ϊ��ת������ʱ��Ŀ�Ĳ��ɴ��ԭ��Ҫ��ת���������Ƴ�
        cout << pkt->ifDiscard() << endl;
        cout << "��ERR�� tryToFwd Error: Packet should be discarded" << endl;
        return;
    }
    if (pkt->getICMPPkt()->IPHeader.TTL == 0) {  //�жϰ���TTL���������Ƿ�Ϊ0�����Ϊ0ɾ������
        cout << "��ERR�� tryToFwd Error: Packet TTL is 0" << endl;
        pkt->setDiscardState(true);  //�Ƴ�״̬
        //����ICMP��ʱ����
        return;
    }
    if (time(NULL) - pkt->getTime() > pktLifetime) {  //����ICMP���ĳ�ʱ���������򣬣�Ӧ�÷���ICMP��ʱ���ģ�
        cout << "��ERR�� tryToFwd Error: Packet lifetime expired" << endl;
        pkt->setDiscardState(true);
        //����ICMP��ʱ����
        return;
    }
    if (deviceManager->findInterfaceIP(pkt->getICMPPkt()->IPHeader.DstIP) != 0) { //ת�������豸�ӿ�λ��ͬһ���Σ�ֱ��Ͷ��
        if ((arpEntry = arpTable->lookup(pkt->getICMPPkt()->IPHeader.DstIP)) == NULL) { //ARP����Ϊ��
            cout << "��ERR�� ARP cache miss. IP: " << IPToString(pkt->getICMPPkt()->IPHeader.DstIP) << endl;
            sendARPReqest(pkt->getICMPPkt()->IPHeader.DstIP);  //����ARP�������ȡMAC��ַ
            return;
        }
        dstMac = arpEntry->getMac();  //��ȡ�豸��Ӧ�� MAC��ַ
        forward(pkt->getICMPPkt(), dstMac);  //ת��
        cout << fwrdLog(pkt->getICMPPkt()->IPHeader.DstIP, dstMac, (int)(pkt->getICMPPkt()->IPHeader.TTL), false) << endl;
        pkt->setDiscardState(true); //�Ƴ�״̬
        return;
    }
    //�豸�ͱ��Ĳ���ͬһ���Σ�����ֱ��Ͷ�ݣ�����·������ת��
    if ((routingEntry = routingTable->lookup(pkt->getICMPPkt()->IPHeader.DstIP)) == NULL) { //·�ɱ���Ϊ�գ�ICMPĿ�Ĳ��ɴ�
        cout << "��ERR�� Routing table miss. IP: " << IPToString(pkt->getICMPPkt()->IPHeader.DstIP) << endl;
        pkt->setDiscardState(true); 
        //����ICMPĿ�Ĳ��ɴﱨ��
        return;
    }
    if ((arpEntry = arpTable->lookup(routingEntry->getGateway())) == NULL) {  //��һ���ӿڵ�ARP����Ϊ��
        cout << "��ERR�� ARP cache miss. IP: " << IPToString(routingEntry->getGateway()) << endl;
        sendARPReqest(routingEntry->getGateway());  //�㲥ARP��ȡMAC��ַ
        return;
    }
    dstMac = arpEntry->getMac();
    forward(pkt->getICMPPkt(), dstMac);  //����һ��ת��
    cout << fwrdLog(routingEntry->getGateway(), dstMac, (int)(pkt->getICMPPkt()->IPHeader.TTL)) << endl;
    pkt->setDiscardState(true);
    return;
}

DWORD WINAPI Router::fwdThrd(LPVOID lpParam)
{
    cout << "��INF�� Forward Thread started!\n";
    Router* router;
    Packet* pkt;
    router = (Router*)lpParam;
    while (true) {
        EnterCriticalSection(&router->getCS()); //�����ٽ���Դ
        pkt = router->getPacketBuf()->getHead();
        while (pkt != NULL) {  //�����������еȴ�ת���İ����Ƴ���Ҫ�Ƴ��İ�
            if (pkt->ifDiscard()) {  
                pkt = router->getPacketBuf()->Delete(pkt);
            }
            else {
                pkt = pkt->getNext();
            }
        }
        pkt = router->getPacketBuf()->getHead();
        if (pkt == NULL) {  //û��Ҫת���İ�
            LeaveCriticalSection(&router->getCS());
            continue;
        }
        router->tryToFwd(router->getPacketBuf()->getHead()); 
        pkt = pkt->getNext();
        LeaveCriticalSection(&router->getCS());  //�ͷ��ٽ���Դ
        while (pkt != NULL) {  //����ת����������������ת����
            router->tryToFwd(pkt);
            pkt = pkt->getNext();
        }
    }
    return 0;
}

DWORD WINAPI Router::rcvThrd(LPVOID lpParam) {
    cout << "��INF�� Receive Thread started!\n";
    Router* router;
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;

    router = (Router*)lpParam;
    while (true) {  //������
        //�õ�pcap_next_ex�ķ��ؽ��
        int result = pcap_next_ex(router->getDeviceManager()->getOpenHandle(), &pkt_header, &pkt_data);
        if (result == 0) //δ�������ݰ�
            continue;
        else {
            if (result == -1) {//���ù��̷�������
                cout << "Error reading the packets: " << pcap_geterr(router->getDeviceManager()->getOpenHandle()) << endl;
                exit(-1);
            }
            else {//result=1������ɹ�
                if (macCmp(router->getDeviceManager()->getOpenDevice()->getMac(), ((FrameHeader_t*)pkt_data)->SrcMac)) // ����Ǳ������������ݰ�����
                    continue;
                switch (ntohs(((FrameHeader_t*)pkt_data)->FrameType)) {
                case 0x0806:  //ARP��ر���
                    if ((ntohs(((ARPFrame_t*)pkt_data)->Operation) == 0x0001)  // �����ARP����������                         
                        || router->getDeviceManager()->findInterfaceIP(((ARPFrame_t*)pkt_data)->SendIP) == 0) // ���߲��뱾���ӿ���ͬһ���Σ������ɴ�����
                        continue;
                    //ARP��Ӧ���ģ����ARP����
                    router->getARPTable()->add(((ARPFrame_t*)pkt_data)->SendIP, ((ARPFrame_t*)pkt_data)->SendHa);
                    break;
                case 0x0800:  //IP����
                    if (((IPFrame_t*)pkt_data)->IPHeader.DstIP == router->getDeviceManager()->getOpenDevice()->getIP(0) // ���Ŀ��IPΪ����IP
                        || ((IPFrame_t*)pkt_data)->IPHeader.DstIP == router->getDeviceManager()->getOpenDevice()->getIP(1)
                        || !macCmp(router->getDeviceManager()->getOpenDevice()->getMac(), ((FrameHeader_t*)pkt_data)->DesMac) // ��Ŀ��MAC��Ϊ����
                        || ifICMPCheckSum((u_short*)pkt_data, sizeof(ICMPFrame_t))) // ��ICMPУ��ʹ���
                        continue;   //����                                                                                         
                    EnterCriticalSection(&router->getCS());
                    router->getPacketBuf()->addBefore((ICMPFrame_t*)pkt_data);  //��Ӱ���ת��������
                    cout << recvLog(((ICMPFrame_t*)pkt_data)->IPHeader.SrcIP, ((ICMPFrame_t*)pkt_data)->FrameHeader.SrcMac, ((ICMPFrame_t*)pkt_data)->IPHeader.DstIP, ((ICMPFrame_t*)pkt_data)->FrameHeader.DesMac, (int)((ICMPFrame_t*)pkt_data)->IPHeader.TTL) << endl;
                    LeaveCriticalSection(&router->getCS());
                    break;
                }
            }
        }
    }
    return 0;
}

int main() {
    freopen("output.txt", "w", stdout); //�������־д���ļ�output.txt
    Router router;
    return 0;
}