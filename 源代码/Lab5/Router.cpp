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
#include "pcap.h"   //添加pca.h包含文件
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
using namespace std;

//定义相关报文格式：IP数据帧、ARP数据帧、不同类型的ICMP数据帧
#pragma pack(1) // 字节对齐

typedef struct FrameHeader_t {  //数据帧首部，14B
    BYTE DesMac[6]; //目的地址
    BYTE SrcMac[6]; //源地址
    WORD FrameType; //帧类型
}FrameHeader_t;

typedef struct IPHeader_t {   // IP首部，20B
    BYTE Ver_HLen;  // 版本和首部包头长度 ，分别占4比特
    BYTE Tos; //服务类型
    WORD TotalLen;  //总长度
    WORD ID;   //标识
    WORD Flag_Segment; //标志
    BYTE TTL;     //生存周期，每经过一次转发就减1
    BYTE Protocol;   //协议
    WORD Checksum;  //头部校验和，针对IP首部的校验和
    ULONG SrcIP;   //源IP地址
    ULONG DstIP;   //目的IP地址
} IPHeader_t;

typedef struct ARPFrame_t {  //ARP帧
    FrameHeader_t FrameHeader;
    WORD HardwareType;//硬件类型，以太网接口类型为1
    WORD ProtocolType;//协议类型，IP类型为0800H
    BYTE HLen;//硬件地址长度，物理地址MAC长度为6B
    BYTE PLen;//协议地址长度，IP地址长度为4B
    WORD Operation;//操作类型，ARP请求报文为1，响应报文为2
    BYTE SendHa[6];//发送方MAC地址
    DWORD SendIP;//发送方IP地址
    BYTE RecvHa[6];//接收方MAC地址
    DWORD RecvIP;//接收方IP地址
} ARPFrame_t;

typedef struct IPFrame_t {  // 包含帧首部和IP首部的IP数据包
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
} IPFrame_t;

typedef struct ICMPData_t {   //ICMP 请求（响应）报文，头部8字节+可选数据
    BYTE Type; //类型
    BYTE Code;  //代码，与类型字段一起标识ICMP报文的详细类型
    WORD Checksum;  //校验和，计算包括ICMP头部和可选数据部分的校验（不包括IP首部）
    WORD Id; //标识符
    WORD Seq;  //序号
    BYTE Data[32];  //选项数据
} ICMPData_t;

typedef struct ICMPFrame_t { //包含帧首部和IP首部的ICMP请求（响应）报文
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
    ICMPData_t ICMPData;
} ICMPFrame_t;

#pragma pack() // 恢复默认对齐方式

class PacketList;

class Packet {  //定义报文类，ICMP请求（响应）报文
private:
    ICMPFrame_t* icmpPkt;
    time_t time;  //启动一个计时器，记录包创建的时间，用于判断是否超时，生存时间
    bool discardState;  //定义移除状态，用于表示包转发过程中是否丢弃
    Packet* prev;  
    Packet* next;
public:
    Packet(ICMPFrame_t* ipPkt, time_t time);
    ~Packet() {};
    ICMPFrame_t* getICMPPkt() const { return icmpPkt; };
    time_t getTime() const { return time; };
    bool ifDiscard() const { return discardState; };  //判断是否丢弃
    void setDiscardState(bool discardState) { this->discardState = discardState; };
    Packet* getNext() { return next; };

    friend class PacketList;
};

class PacketList {  //报文链表类，双向链表
private:
    Packet* head;  //头节点
    Packet* tail; //尾部
    u_int size; //报文数量
public:
    PacketList();
    ~PacketList();
    void addBefore(ICMPFrame_t* icmpPkt);  //在链表头部插入报文，等待转发
    Packet* Delete(Packet* packet);  //删除指定包
    Packet* getHead() const { return head; };
    u_int getSize() const { return size; };
};

class DeviceManager;

class Device {   //网卡设备类，每个设备有两个IP地址，一个MAC地址
private:
    string name;    // 设备名称
    string description; // 设备描述
    DWORD ip[2];        // IP地址
    DWORD subnetMask[2];    // 子网掩码
    BYTE mac[6];    // MAC地址

public:
    Device();
    ~Device();
    DWORD getIP(u_int idx = 0);
    DWORD getSubnetMask(u_int idx = 0);
    BYTE* getMac();
    string toStr();

    friend class DeviceManager;

};

class DeviceManager {  //设备管理类，设备链表
private:
    u_int deviceNum;  //网卡设备数目
    Device* deviceList;  //设备列表，数组
    Device* openDevice;  //打开的网卡设备
    pcap_t* openHandle; //打开句柄

public:
    DeviceManager();
    ~DeviceManager();
    u_int getDeviceNum() { return deviceNum; };
    Device* getOpenDevice() { return openDevice; };
    pcap_t* getOpenHandle() { return openHandle; };
    string toStr();
    void selectOpenDevice();         // 查找所有网卡,选择网卡并打开，获得打开网卡句柄
    void setMac(BYTE* mac, Device* device);   // 设置指定网卡设备的MAC地址
    DWORD findInterfaceIP(DWORD ip);    // 根据IP地址，查看和打开网卡是否在同一网段，返回对应的接口IP地址
};

class ARPTable;             // ARP表，双向链表存储

class ARPEntry {    //ARP表项
private:
    DWORD ip;               // IP地址
    BYTE mac[6];            // MAC地址
    time_t time;            // 计时器，作为ARP表项的添加时间，超过符号表的老化时间则从表中删除
    ARPEntry* prev;  //前指针
    ARPEntry* next;  //下一个指针
    friend class ARPTable;

public:
    ARPEntry(DWORD ip, BYTE* mac, time_t time);
    ~ARPEntry() {};
    BYTE* getMac();  //得到符号表项的MAC地址
    string toStr(bool showAttr = true);
};

class ARPTable {   //ARP表
private:
    ARPEntry* head;  //头部
    ARPEntry* tail; //尾部
    u_int size;  //ARP表项个数
    u_int agingTime;  //ARP表的老化时间

public:
    ARPTable();
    ~ARPTable();
    void add(DWORD ip, BYTE* mac); //添加ARP表项，加在链表尾部
    void Delete(ARPEntry* arpEntry);  //删除指定ARP表项
    ARPEntry* lookup(DWORD ip);  //寻找指定IP的ARP表项，从而获取MAC地址
    bool isExpired(ARPEntry* arpEntry) ;  //判断ARP表项是否超时，符号表项时间>ARP表老化时间
    string toStr();
};

class RoutingTable;

class RoutingEntry {  //路由表项
private:
    DWORD dest;         // 目的网络
    DWORD netmask;      // 子网掩码
    DWORD gateway;           // 网关地址，下一跳的IP地址
    DWORD interfaceIP;          // 转发路由接口的IP地址
    RoutingEntry* prev;
    RoutingEntry* next;

    friend class RoutingTable;

public:
    RoutingEntry(DWORD dest, DWORD netmask, DWORD gateway, DWORD interfaceIP);
    ~RoutingEntry() {};
    DWORD getGateway() { return this->gateway; };
    string toStr(bool showAttr = true);
};

class RoutingTable {  //路由表，双向链表
private:
    Device* openDevice;  //打开的设备指针，表示该设备的路由表
    RoutingEntry* head;
    RoutingEntry* tail;
    u_int size;  //路由表项的个数

public:
    RoutingTable(Device* openDevice);
    ~RoutingTable();
    void add(DWORD dest, DWORD netmask, DWORD gateway);  //添加路由表项，每次添加都放在路由表末尾
    void add(const char* dest, const char* netmask, const char* gateway);
    void Delete(RoutingEntry* routingEntry);  //删除指定路由表项
    RoutingEntry* lookup(DWORD dest);  //查找目的IP对应的路由表项，下一跳，最长匹配原则，每次查找从头开始遍历
    RoutingEntry* lookup(char* dest);
    string toStr();
};

class Router {  //路由器大类
private:
    DeviceManager* deviceManager;  //路由器设备
    ARPTable* arpTable;  //该路由器的ARP表
    RoutingTable* routingTable;  //该路由器的路由表
    PacketList* packetBuf;  //转发包缓冲区
    u_int pktLifetime;  //每个包在缓冲区中的生存时间，超时则丢弃
    HANDLE hFwdThrd;  //转发线程
    HANDLE hRcvThrd;  //接受线程
    CRITICAL_SECTION cs;  //访问资源临界区
public:
    Router();
    ~Router();
    DeviceManager* getDeviceManager() { return deviceManager; };
    ARPTable* getARPTable() { return arpTable; };
    RoutingTable* getRoutingTable() { return routingTable; };
    PacketList* getPacketBuf() { return packetBuf; };
    u_int getPktLifetime() { return pktLifetime; };
    CRITICAL_SECTION& getCS() { return cs; };

    BYTE* getOpenDeviceMac(Device* device);         // 获取IP地址与MAC地址映射，如果APR表中没有，则广播ARP获取
    void cmdInput();                                 // 主线程中输入路由器的相关指令
    bool sendARPReqest(DWORD ip);                   // 广播ARP请求，获得指定设备IP对应的MAC地址
    void forward(ICMPFrame_t* pkt, BYTE* dstMac);   // 转发ICMP数据包到指定目的IP
    void tryToFwd(Packet* pkt);       // 尝试调用forward函数转发ICMP数据包，由转发线程调用
    static DWORD WINAPI fwdThrd(LPVOID lpParam);    // 转发线程函数
    static DWORD WINAPI rcvThrd(LPVOID lpParam);    // 接收线程函数
};

//一些辅助函数
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

bool macCmp(BYTE* mac1, BYTE* mac2) { //判断两个MAC地址是否相同
    if (mac2 == NULL) {
        return memcmp(mac1, "\0\0\0\0\0\0", 6) == 0;
    }
    else {
        return memcmp(mac1, mac2, 6) == 0;
    }
}

string recvLog(DWORD srcIP, BYTE* srcMac, DWORD dstIP, BYTE* dstMac, int ttl) {  //接受日志输出
    string str = "";
    string temp;
    str += "【INF】 Packet Received: \nSrcIP           SrcMac            DstIP           DstMac            TTL\n";
    temp = IPToString(srcIP); temp.resize(16, ' '); str += temp;
    temp = MacToString(srcMac); temp.resize(18, ' '); str += temp;
    temp = IPToString(dstIP); temp.resize(16, ' '); str += temp;
    temp = MacToString(dstMac); temp.resize(18, ' '); str += temp;
    temp = intToString(ttl); str += temp;
    return str;
}

string fwrdLog(DWORD dstIP, BYTE* dstMac, int ttl, bool nextHop=true) { //转发日志输出
    string str = "";
    string temp;
    if (nextHop) {
        str += "【INF】 Packet Forwarded: \nNextHop         DstMac            TTL\n";
    }
    else {
        str += "【INF】 Packet Forwarded: \nDstIP           DstMac            TTL\n";
    }
    temp = IPToString(dstIP); temp.resize(16, ' '); str += temp;
    temp = MacToString(dstMac); temp.resize(18, ' '); str += temp;
    temp = intToString(ttl); str += temp;
    return str;
}

ARPFrame_t* makeARPRequestPkt(u_char* dstMac, u_char* srcMac,DWORD dstIP, DWORD srcIP) { //组装ARP请求报文
    ARPFrame_t* ARPFrame = new ARPFrame_t;
    memcpy(ARPFrame->FrameHeader.DesMac, dstMac, 6);
    memcpy(ARPFrame->FrameHeader.SrcMac, srcMac, 6);
    ARPFrame->FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
    ARPFrame->HardwareType = htons(0x0001);//硬件类型为以太网
    ARPFrame->ProtocolType = htons(0x0800);//协议类型为IP
    ARPFrame->HLen = 6;//硬件地址长度为6
    ARPFrame->PLen = 4; // 协议地址长为4
    ARPFrame->Operation = htons(0x0001);//操作为ARP请求
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

u_short addIPPktCheckSum(u_short* pkt_data, int len) {  //计算IP首部的校验和（不包含以太网帧首部）,len为以太网帧首部+IP头
    u_long sum;
    u_short basic;
    u_short* pointer;
    sum = 0;
    basic = ((IPFrame_t*)pkt_data)->IPHeader.Checksum;  //原本的校验和
    pointer = pkt_data;  //原本的报文指针位置
    ((IPFrame_t*)pkt_data)->IPHeader.Checksum = 0;  //校验和更新为0
    pkt_data = (u_short*)&(((IPFrame_t*)pkt_data)->IPHeader);  //获取IP首部
    len -= sizeof(FrameHeader_t); //减去以太网帧首部
    while (len > 1) {  //16比特为单位
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
    return (u_short)(~sum);  //校验和取反
}

u_short addICMPChecksum(u_short* pkt_data, int len) {  //计算ICMP报文的校验和：ICMP头部+ICMP数据，不包括IP首部
    u_long sum;
    u_short basic;
    u_short* pointer;
    sum = 0;
    basic = ((ICMPFrame_t*)pkt_data)->ICMPData.Checksum;
    pointer = pkt_data;
    ((ICMPFrame_t*)pkt_data)->ICMPData.Checksum = 0;
    pkt_data = (u_short*)&((ICMPFrame_t*)pkt_data)->ICMPData; //定位到ICMP头部位置
    len -= (sizeof(FrameHeader_t)+sizeof(IPHeader_t)); //长度减去以太网帧首部和IP首部
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

bool ifICMPCheckSum(u_short* pkt_data, int len) {  //判断ICMP报文校验和，是否出错
    u_long sum;
    sum = 0;
    pkt_data = (u_short*)&((ICMPFrame_t*)pkt_data)->ICMPData;
    len -= (sizeof(FrameHeader_t) + sizeof(IPHeader_t)); //长度减去以太网帧首部和IP首部
    while (len > 1) {
        sum += *pkt_data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char*)pkt_data;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    if (sum != 0xffff) {  //结果不是全1，校验和错误
        cout << "【ERR】 ICMP checksum error" << endl;
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
            cout << "【ERR】 Get IP Error: subnetMask[" << idx << "] is not set." << endl;
        }
    }
    else {
        cout << "【ERR】 Get IP Error: idx out of range." << endl;
        exit(1);
    }
    return ip[idx];
}

DWORD Device::getSubnetMask(u_int idx) {
    if (idx < 2) {
        if (subnetMask[idx] == 0) {
            cout << "【ERR】 Get Subnet Mask Error: subnetMask[" << idx << "] is not set." << endl;
        }
    }
    else {
        cout << "【ERR】 Get Subnet Mask Error: idx: " << idx << " out of range." << endl;
        exit(1);
    }
    return subnetMask[idx];
}

BYTE* Device::getMac() {
    BYTE temp[6];
    memset(temp, 0, 6);
    if (memcmp(mac, temp, 6) == 0) {
        cout << "【ERR】 Get MAC Error: mac is not set." << endl;
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
    pcap_if_t* alldevs; //指向设备链表首部的指针
    pcap_if_t* d;
    pcap_addr_t* a;
    char errbuf[PCAP_ERRBUF_SIZE];  //错误信息缓冲区

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {  // 获取本机网卡列表,
        cout << "【ERR】 Error in pcap_findalldevs: " << errbuf << endl; //获取网络接口列表失败，结束程序
        exit(1);
    }
    for (d = alldevs; d != NULL; d = d->next) { // 获取设备数量
        deviceNum++;
    }
    if (deviceNum == 0) { //网络接口设备为0
        cout << "【ERR】 No device found! Make sure WinPcap is installed." << endl;
        exit(1);
    }
    deviceList = new Device[deviceNum];
    int i = 0;
    for (d = alldevs; d != NULL; d = d->next) { //遍历设备链表，获取设备名和描述
        deviceList[i].name = string(d->name);
        deviceList[i].description = string(d->description);
        int j;
        for (j = 0, a = d->addresses; j < 2 && a != NULL; a = a->next) {    // 获取设备的两个IP地址
            if (a->addr->sa_family == AF_INET) {//判断该地址是否为IP地址
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
    cout << "【SUC】 Find Devices Success! Devices： " << endl;
    cout << toStr() << endl;
    //选择网络设备并打开
    u_int id;
    cout << "【CMD】 Please input the device index: ";
    cin >> id;  //输入要打开的网络设备
    if (id < 1 || id > deviceNum) {
        cout << "【ERR】 Invalid device index" << endl;
        exit(1);
    }
    id--;
    openDevice = &deviceList[id];  //获得打开的网络设备
    if ((openHandle = pcap_open(openDevice->name.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) ==NULL) { // 打开网卡
        cout << "【ERR】 Error in pcap_open_live: " << errbuf << endl;
        exit(1);
    }
   if (pcap_datalink(openHandle) != DLT_EN10MB) { // 判断网卡是否为以太网适用
        cout << "【ERR】 This device is not an Ethernet" << endl;
        exit(1);
    }
    if (pcap_setnonblock(openHandle, 1, errbuf) == -1) { // 设置网卡为非阻塞模式
        cout << "【ERR】 Error in pcap_setnonblock: " << errbuf << endl;
        exit(1);
    }
    cout << "【SUC】 Device opened successfully" << endl;
}

void DeviceManager::setMac(BYTE* mac, Device* device) {
    if (mac == NULL) {
        cout << "【ERR】 Set MAC Error: mac is NULL." << endl;
        return;
    }
    if (device == NULL) {
        cout << "【ERR】 Set MAC Error: device is NULL." << endl;
    }
    if (device->getMac() != NULL) {
        cout << "【ERR】 Set MAC Error: mac is already set." << endl;
        return;
    }
    memcpy(device->mac, mac, 6);
}

DWORD DeviceManager::findInterfaceIP(DWORD ip) {
    if (openDevice == NULL) {
        cout << "【ERR】 Find Itf Error: openDevice is NULL." << endl;
        return 0;
    }
    if (openHandle == NULL) {
        cout << "【ERR】 Find Itf Error: openHandle is NULL." << endl;
        return 0;
    }
    if ((ip & openDevice->subnetMask[0]) == (openDevice->ip[0] & openDevice->subnetMask[0])) {
        return openDevice->ip[0];  //和接口0网络号相同，ip地址 逻辑与 掩码
    }
    if ((ip & openDevice->subnetMask[1]) == (openDevice->ip[1] & openDevice->subnetMask[1])) {
        return openDevice->ip[1];  //和接口1网络号相同
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
        cout << "【ERR】 Get MAC Error: mac is not set." << endl;
        return NULL;
    }
    return mac;
}

string ARPEntry::toStr(bool showAttr) {
    string str = "";
    string temp;
    if (showAttr) {  //输出IP地址、MAC地址、更新时间
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
    this->agingTime = 60;  //ARP表的老化时间设置为60s
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
    if (lookup(ip) != NULL) { //指定IP的ARP表项已经存在
        return;
    }
    arpEntry = new ARPEntry(ip, mac, time(NULL));  //构造符号表项添加，启动计时器
    cout << "【INF】 Add ARP Entry: " << arpEntry->toStr(false) << endl;
    if (head == NULL) {  //头指针为0.更新
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
    cout << "【INF】 Delete ARP Entry: " << arpEntry->toStr(false) << endl;
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
        if (arpEntry->ip == ip) {  //找到IP对应的ARP表项
            return arpEntry;
        }
        arpEntry = arpEntry->next;
    }
    return NULL;
}

bool ARPTable::isExpired(ARPEntry* arpEntry) {  //是否超时
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

string RoutingEntry::toStr(bool showAttr) { //路由表项输出：目的网络 掩码 网关(下一跳地址) 接口(转发接口的IP地址)
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
    //路由表项已存在
    if ((routingEntry = lookup(dest)) != NULL && (routingEntry->netmask != 0)) {
        return;
    }
    switch (netmask) {  //根据给定的gateway网关IP判断，是否属于路由的转发接口，根据网络号判断：IP & 子网掩码
    case 0:  //子网掩码为0，添加默认路由
        if ((openDevice->getIP(0) & openDevice->getSubnetMask(0)) == (gateway & openDevice->getSubnetMask(0))) {
            interfaceIP = openDevice->getIP(0);
        }
        else if ((openDevice->getIP(1) & openDevice->getSubnetMask(1)) == (gateway & openDevice->getSubnetMask(1))) {
            interfaceIP = openDevice->getIP(1);
        }
        else { //给的网关IP地址不是路由的接口
            cout << "【ERR】 Add Routing Entry Error: default destination is unreachable" << endl;
            return;
        }
        routingEntry = new RoutingEntry(0, 0, gateway, interfaceIP); //默认路由，目的网络和掩码都为0
        break;
    default:  //添加普通路由
        if ((openDevice->getIP(0) & openDevice->getSubnetMask(0)) == (gateway & openDevice->getSubnetMask(0))) {
            interfaceIP = openDevice->getIP(0);
        }
        else if ((openDevice->getIP(1) & openDevice->getSubnetMask(1)) == (gateway & openDevice->getSubnetMask(1))) {
            interfaceIP = openDevice->getIP(1);
        }
        else {
            cout << "【ERR】 Add Routing Entry Error: No interface found for this destination." << endl;
            return;
        }
        routingEntry = new RoutingEntry(dest & netmask, netmask, gateway, interfaceIP); //添加普通路由
    }
    //添加在链表尾部
    if (head == NULL) {
        head = tail = routingEntry;
    }
    else {
        tail->next = routingEntry;
        routingEntry->prev = tail;
        tail = routingEntry;
    }
    size++;
    cout << "【INF】 Routing Entry Added： " << routingEntry->toStr(false) << endl;
}

void RoutingTable::add(const char* dest, const char* netmask, const char* gw) {
    add(inet_addr(dest), inet_addr(netmask), inet_addr(gw));
}

void RoutingTable::Delete(RoutingEntry* routingEntry) {
    if (routingEntry == NULL) {
        cout << "【ERR】 Delete Routing Entry Error: Routing entry not found." << endl;
        return;
    }
    if (size == 0) {
        cout << "【ERR】 Delete Routing Entry Error: Routing table is empty." << endl;
        return;
    }
    cout << "【INF】 Delete Routing Entry: " << routingEntry->toStr(false) << endl;
    if (routingEntry->prev == NULL) {  //前指针为空
        head = routingEntry->next;
    }
    else {
        routingEntry->prev->next = routingEntry->next;
    }
    if (routingEntry->next == NULL) {  //后指针为空
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
    DWORD maxPrefixNetmask;  //最长匹配掩码

    routingEntry = head;
    if (routingEntry == NULL) {  //路由表为空
        cout << "【ERR】 Look up Routing Table Error: Routing table is empty." << endl;
        return NULL;
    }
    result = NULL;
    maxPrefixNetmask = head->netmask;
    while (routingEntry != NULL) {  //从头遍历路由表链表
        //判断网络号是否相等：目的IP & 掩码
        if ((routingEntry->dest & routingEntry->netmask) == (dest & routingEntry->netmask)) {  //网络号相等
            if (ntohl(routingEntry->netmask) > ntohl(maxPrefixNetmask)) { //判断掩码长度，最长匹配
                maxPrefixNetmask = routingEntry->netmask; //更新更长的掩码
                result = routingEntry;
            }
            //result = routingEntry;
        }
        routingEntry = routingEntry->next;
    }
    if (result == NULL) {  //没有找到
        cout << "【ERR】 Look up Routing Table Error: Routing entry not found." << endl;
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
    deviceManager->selectOpenDevice();       //查找所有网络设备，选择打开的网卡
    getOpenDeviceMac(deviceManager->getOpenDevice()); // 获取打开设备的Mac地址

    packetBuf = new PacketList();
    pktLifetime = 10; // 数据包在缓冲区允许的最大生存时间
    arpTable = new ARPTable();
    routingTable = new RoutingTable(deviceManager->getOpenDevice());
    routingTable->add("0.0.0.0", "0.0.0.0", "206.1.2.2");   // 添加默认路由，不可删除，可修改

    InitializeCriticalSection(&cs);
    hFwdThrd = CreateThread(NULL, 0, fwdThrd, this, 0, NULL); // 创建转发线程
    Sleep(100);
    hRcvThrd = CreateThread(NULL, 0, rcvThrd, this, 0, NULL); // 创建接收线程
    Sleep(100);
    cmdInput();     // 主线程进输入命令行指令
}

Router::~Router() {
    delete deviceManager;
    delete arpTable;
    delete routingTable;
    CloseHandle(hRcvThrd);
    CloseHandle(hFwdThrd);
    DeleteCriticalSection(&cs);
}

BYTE* Router::getOpenDeviceMac(Device* device) { // 使用ARP协议获取指定网卡设备的MAC地址
    BYTE RecvHa[6];
    BYTE SendHa[6];
    DWORD RevIP;
    DWORD SendIP;
    ARPFrame_t* ARPFrame;  //ARP请求包
    ARPFrame_t* captureARPPkt; //捕获到的ARP响应包
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;

    if (device == NULL) {
        cout << "【ERR】 Get Open Device Error: No device opened!" << endl;
        return NULL;
    }
    if (device->getMac() != NULL) { // 如果已经获取过MAC地址，直接返回，否则通过ARP协议获取
        return device->getMac();
    }

    memset(RecvHa, 0xff, 6);                            // 目的MAC地址为广播地址
    memset(SendHa, 0x66, 6);                            // 源MAC地址为虚假的66-66-66-66-66-66
    RevIP = deviceManager->getOpenDevice()->getIP(0);            // 目的IP地址为网卡IP地址
    SendIP = inet_addr("112.112.112.112");                        // 伪造源IP地址
    ARPFrame = makeARPRequestPkt(RecvHa, SendHa, SendIP, RevIP);     // 虚构地址的ARP请求数据包

    //模拟远端主机的ARP请求，捕获本机的ARP响应，获取本机网络接口MAC地址
    if (pcap_sendpacket(deviceManager->getOpenHandle(), (u_char*)ARPFrame, sizeof(ARPFrame_t)) != 0) {
        cout << "【ERR】 Get Open Device Error: Error in pcap_sendpacket: " << pcap_geterr(deviceManager->getOpenHandle()) << endl;
        exit(1);
    }
    while (true) {
        int result = pcap_next_ex(deviceManager->getOpenHandle(), &pkt_header, &pkt_data); //得到pcap_next_ex的返回结果
        if (result == 0) {  //未捕获到数据包
            continue;
        }
        else if (result == -1) {  //调用过程发生错误
            cout << "【ERR】 Get Open Device Error: Error in reading the packets: " << pcap_geterr(deviceManager->getOpenHandle()) << endl;
            exit(-1);
        }
        else {  //result=1，捕获成功
            captureARPPkt = (ARPFrame_t*)pkt_data;  //捕获到的数据包转化为自定义的ARPFrame_t数据包类型
            //判断捕获的IP包是否为之前发的ARP请求的响应包
            if (ntohs(captureARPPkt->FrameHeader.FrameType) == 0x0806 && ntohs(captureARPPkt->Operation) == 0x0002 && captureARPPkt->RecvIP == SendIP && captureARPPkt->SendIP == RevIP) {
                cout << "【INF】 ARP Reply To Open Device Received" << endl;
                deviceManager->setMac(captureARPPkt->FrameHeader.SrcMac, device);  //设置MAC地址
                break;
            }
        }
    }
    cout << "【SUC】 Get IP-MAC map successfully. Open device info :" << endl;
    cout << deviceManager->getOpenDevice()->toStr() << endl;
    return device->getMac();
}

void Router::cmdInput() {
    cout << "=========================================================\n";
    cout << "【CMD】Command Thread started. Cmds listed bellow\n";
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
        cout << "【CMD】 Please input command: ";
        cin.getline(cmd, 50);  //输入指令

        char* p;
        vector<string> cmdVec;
        if (string(cmd) == "") {
            cout << "【CMD】 Command empty!" << endl;
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
                    cout << "【ERR】 Cannot delete default route!" << endl;
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
    ARPFrame_t* ARPFrame; //广播ARP请求报文

    if (ip == 0) {
        cout << "【ERR】 bcstARPReq Error: dest ip is NULL" << endl;
        return false;
    }
    if (deviceManager->getOpenDevice() == NULL) {
        cout << "【ERR】 bcstARPReq Error: openDevice is NULL" << endl;
        return false;
    }
    if ((srcIP = deviceManager->findInterfaceIP(ip)) == 0) {
        cout << "【ERR】 bcstARPReq Error: ip is not destined locally" << endl;
        return false;
    }
    memset(dstMac, 0xff, 6);  //目的MAC地址为广播地址
    memcpy(srcMac, deviceManager->getOpenDevice()->getMac(), 6);  //源地址为打开设备的接口MAC地址
    dstIP = ip;
    ARPFrame = makeARPRequestPkt(dstMac, srcMac, srcIP, dstIP); //组装ARP请求报文
    //广播ARP报文
    if (pcap_sendpacket(deviceManager->getOpenHandle(), (u_char*)ARPFrame, sizeof(ARPFrame_t)) != 0) {
        cout << "【ERR】 bcstARPReq Error: Error in pcap_sendpacket: " << pcap_geterr(deviceManager->getOpenHandle()) << endl;
        return false;
    }
    return true;
}

void Router::forward(ICMPFrame_t* pkt, BYTE* dstMac) {
    if (pkt == NULL) {
        cout << "【ERR】 Fwd Pkt Error: Invalid packet!" << endl;
        return;
    }
    if (dstMac == NULL) {
        cout << "【ERR】 Fwd Pkt Error: Invalid destination MAC address!" << endl;
        return;
    }
    memcpy(pkt->FrameHeader.SrcMac, deviceManager->getOpenDevice()->getMac(), 6);
    memcpy(pkt->FrameHeader.DesMac, dstMac, 6);
    pkt->IPHeader.TTL--;  //每转发一次，生存时间减1
    setICMPChecksum((u_short*)pkt);  //重新计算校验和
    if (pcap_sendpacket(deviceManager->getOpenHandle(), (u_char*)pkt, sizeof(ICMPFrame_t)) != 0) {
        cout << "【ERR】 Fwd Pkt Error: Error in pcap_sendpacket: " << pcap_geterr(deviceManager->getOpenHandle()) << endl;
        exit(1);
    }
}

void Router::tryToFwd(Packet* pkt) {
    if (pkt == NULL) {
        cout << "【ERR】 tryToFwd Error: pkt is NULL" << endl;
        return;
    }
    BYTE* dstMac;
    RoutingEntry* routingEntry;
    ARPEntry* arpEntry;

    if (pkt->ifDiscard()) {  //判断包移除状态，是否因为已转发、超时、目的不可达等原因要从转发缓冲区移除
        cout << pkt->ifDiscard() << endl;
        cout << "【ERR】 tryToFwd Error: Packet should be discarded" << endl;
        return;
    }
    if (pkt->getICMPPkt()->IPHeader.TTL == 0) {  //判断包的TTL生存周期是否为0，如果为0删除报文
        cout << "【ERR】 tryToFwd Error: Packet TTL is 0" << endl;
        pkt->setDiscardState(true);  //移除状态
        //发送ICMP超时报文
        return;
    }
    if (time(NULL) - pkt->getTime() > pktLifetime) {  //发送ICMP报文超时，结束程序，（应该发送ICMP超时报文）
        cout << "【ERR】 tryToFwd Error: Packet lifetime expired" << endl;
        pkt->setDiscardState(true);
        //发送ICMP超时报文
        return;
    }
    if (deviceManager->findInterfaceIP(pkt->getICMPPkt()->IPHeader.DstIP) != 0) { //转发包和设备接口位于同一网段，直接投递
        if ((arpEntry = arpTable->lookup(pkt->getICMPPkt()->IPHeader.DstIP)) == NULL) { //ARP表项为空
            cout << "【ERR】 ARP cache miss. IP: " << IPToString(pkt->getICMPPkt()->IPHeader.DstIP) << endl;
            sendARPReqest(pkt->getICMPPkt()->IPHeader.DstIP);  //发送ARP请求包获取MAC地址
            return;
        }
        dstMac = arpEntry->getMac();  //获取设备对应的 MAC地址
        forward(pkt->getICMPPkt(), dstMac);  //转发
        cout << fwrdLog(pkt->getICMPPkt()->IPHeader.DstIP, dstMac, (int)(pkt->getICMPPkt()->IPHeader.TTL), false) << endl;
        pkt->setDiscardState(true); //移除状态
        return;
    }
    //设备和报文不是同一网段，不能直接投递，经过路由器的转发
    if ((routingEntry = routingTable->lookup(pkt->getICMPPkt()->IPHeader.DstIP)) == NULL) { //路由表项为空，ICMP目的不可达
        cout << "【ERR】 Routing table miss. IP: " << IPToString(pkt->getICMPPkt()->IPHeader.DstIP) << endl;
        pkt->setDiscardState(true); 
        //发送ICMP目的不可达报文
        return;
    }
    if ((arpEntry = arpTable->lookup(routingEntry->getGateway())) == NULL) {  //下一跳接口的ARP表项为空
        cout << "【ERR】 ARP cache miss. IP: " << IPToString(routingEntry->getGateway()) << endl;
        sendARPReqest(routingEntry->getGateway());  //广播ARP获取MAC地址
        return;
    }
    dstMac = arpEntry->getMac();
    forward(pkt->getICMPPkt(), dstMac);  //向下一跳转发
    cout << fwrdLog(routingEntry->getGateway(), dstMac, (int)(pkt->getICMPPkt()->IPHeader.TTL)) << endl;
    pkt->setDiscardState(true);
    return;
}

DWORD WINAPI Router::fwdThrd(LPVOID lpParam)
{
    cout << "【INF】 Forward Thread started!\n";
    Router* router;
    Packet* pkt;
    router = (Router*)lpParam;
    while (true) {
        EnterCriticalSection(&router->getCS()); //进入临界资源
        pkt = router->getPacketBuf()->getHead();
        while (pkt != NULL) {  //遍历缓冲区中等待转发的包，移除需要移除的包
            if (pkt->ifDiscard()) {  
                pkt = router->getPacketBuf()->Delete(pkt);
            }
            else {
                pkt = pkt->getNext();
            }
        }
        pkt = router->getPacketBuf()->getHead();
        if (pkt == NULL) {  //没有要转发的包
            LeaveCriticalSection(&router->getCS());
            continue;
        }
        router->tryToFwd(router->getPacketBuf()->getHead()); 
        pkt = pkt->getNext();
        LeaveCriticalSection(&router->getCS());  //释放临界资源
        while (pkt != NULL) {  //遍历转发包缓冲区，尝试转发包
            router->tryToFwd(pkt);
            pkt = pkt->getNext();
        }
    }
    return 0;
}

DWORD WINAPI Router::rcvThrd(LPVOID lpParam) {
    cout << "【INF】 Receive Thread started!\n";
    Router* router;
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;

    router = (Router*)lpParam;
    while (true) {  //捕获报文
        //得到pcap_next_ex的返回结果
        int result = pcap_next_ex(router->getDeviceManager()->getOpenHandle(), &pkt_header, &pkt_data);
        if (result == 0) //未捕获到数据包
            continue;
        else {
            if (result == -1) {//调用过程发生错误
                cout << "Error reading the packets: " << pcap_geterr(router->getDeviceManager()->getOpenHandle()) << endl;
                exit(-1);
            }
            else {//result=1，捕获成功
                if (macCmp(router->getDeviceManager()->getOpenDevice()->getMac(), ((FrameHeader_t*)pkt_data)->SrcMac)) // 如果是本机发出的数据包则丢弃
                    continue;
                switch (ntohs(((FrameHeader_t*)pkt_data)->FrameType)) {
                case 0x0806:  //ARP相关报文
                    if ((ntohs(((ARPFrame_t*)pkt_data)->Operation) == 0x0001)  // 如果是ARP请求报文则丢弃                         
                        || router->getDeviceManager()->findInterfaceIP(((ARPFrame_t*)pkt_data)->SendIP) == 0) // 或者不与本机接口在同一网段，即不可达的情况
                        continue;
                    //ARP响应报文，添加ARP表项
                    router->getARPTable()->add(((ARPFrame_t*)pkt_data)->SendIP, ((ARPFrame_t*)pkt_data)->SendHa);
                    break;
                case 0x0800:  //IP报文
                    if (((IPFrame_t*)pkt_data)->IPHeader.DstIP == router->getDeviceManager()->getOpenDevice()->getIP(0) // 如果目的IP为本机IP
                        || ((IPFrame_t*)pkt_data)->IPHeader.DstIP == router->getDeviceManager()->getOpenDevice()->getIP(1)
                        || !macCmp(router->getDeviceManager()->getOpenDevice()->getMac(), ((FrameHeader_t*)pkt_data)->DesMac) // 或目的MAC不为本机
                        || ifICMPCheckSum((u_short*)pkt_data, sizeof(ICMPFrame_t))) // 或ICMP校验和错误
                        continue;   //丢弃                                                                                         
                    EnterCriticalSection(&router->getCS());
                    router->getPacketBuf()->addBefore((ICMPFrame_t*)pkt_data);  //添加包到转发缓冲区
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
    freopen("output.txt", "w", stdout); //将输出日志写入文件output.txt
    Router router;
    return 0;
}