#include<iostream>
#include "winsock2.h"
#include "pcap.h"   //添加pca.h包含文件
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
using namespace std;

#pragma pack(1) //以1字节对齐
typedef struct FrameHeader_t {  //定义以太网帧首部
	BYTE DesMac[6]; //目的地址
	BYTE SrcMac[6]; //源地址
	WORD FrameType; //帧类型
}FrameHeader_t;

typedef struct ARPFrame_t {//ARP帧
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
}ARPFrame_t;

#pragma pack()  //恢复默认对齐方式

int main() {
	pcap_if_t* alldevs; //指向设备链表首部的指针
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];  //错误信息缓冲区
	ARPFrame_t ARPFrame;
	DWORD SendIP;
	DWORD RevIP;
	struct pcap_pkthdr* pkt_header;//保存了捕获数据包的基本信息，比如捕获的时间戳、数据包的长度等
	const u_char* pkt_data;  //指向捕获到的数据包
	ARPFrame_t* IPPacket=NULL; //捕获到的ARP响应包

	//获取本机网络接口设备链表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		cout<< "获取设备列表失败" << endl;  //获取网络接口列表失败，结束程序
		return 0;
	}
	int i = 0;
	for (d = alldevs; d != NULL; d = d->next) { //遍历设备链表，显示IP
		//获取当前网络接口设备的IP地址信息
		i++;
		cout << "网卡 " << i << " " << d->name << endl;
		cout<<"描述信息：" << d->description <<endl;
		for (a = d->addresses; a != NULL; a = a->next) {
			if ((a->addr->sa_family == AF_INET)) {  //判断该地址是否为IP地址
				//将a->addr转化为sockaddr_in类型获取网络字节序的IP地址，inet_ntop将其转化为点分十进制的IP
				char address[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(((struct sockaddr_in*)a->addr)->sin_addr), address, sizeof(address));
				cout << "IP地址：" << address<< endl;
				inet_ntop(AF_INET, &(((struct sockaddr_in*)a->netmask)->sin_addr), address, sizeof(address));
				cout << "子网掩码：" << address << endl;
			}
		}
		cout << endl;
	}
	//打开相应的网卡
	int id;
	cout << "请选择网卡：";
	cin >>id;
	cout << endl;
	d = alldevs;
	for (int i = 1; i < id; i++) {
		d = d->next;
		if (d == NULL) {
			cout << "输入网卡不存在" << endl;
			return 0;
		}
	}

	//打开网卡
	pcap_t* pcap_handle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (pcap_handle == NULL) {
		cout << "打开网卡失败" << endl;
		return 0;
	}
	//设置过滤规则，过滤ARP包
	u_int netmask;
	netmask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program fcode;  //存放编译后的规则
	char packet_filter[] = "ether proto \\arp";//过滤规则，ether表示以太网头部，以太网头部proto字段值为0x0806，即ARP
	if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) < 0) 
	{
		cout << "无法编译数据包过滤器。检查语法";
		pcap_freealldevs(alldevs);
		return 0;
	}
	//设置过滤器
	if (pcap_setfilter(pcap_handle, &fcode) < 0)
	{
		cout << "过滤器设置错误";
		pcap_freealldevs(alldevs);
		return 0;
	}

	//组装报文
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMac[i] = 0xFF;//设置为本机广播地址255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMac[i] = 0x66;//设置为虚拟的MAC地址66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;//设置为0，因为此时的硬件目的MAC地址还未确定
		ARPFrame.SendHa[i] = 0x66; //设置为虚假的MAC地址66-66-66-66-66-66
	} 
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4; // 协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	SendIP = ARPFrame.SendIP = htonl(0x70707070);//源IP地址设置为虚拟的IP地址 112.112.112.112
	//将所选择的网卡的IP设置为请求的IP地址
	for (a = d->addresses; a != NULL; a = a->next){
		if (a->addr->sa_family == AF_INET){
			RevIP = ARPFrame.RecvIP = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
		}
	}
	//模拟远端主机的ARP请求，捕获本机的ARP响应，获取本机网络接口MAC地址
	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP请求发送失败" << endl;
	}
	else {
		cout << "ARP请求发送成功" << endl;
		while (true) {
			

			int result = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data); //得到pcap_next_ex的返回结果
			if (result == 0) {  //未捕获到数据包
				cout << "在指定时间范围（read_timeout)内未捕获到数据包" << endl;
				continue;
			}
			else if (result == -1) {  //调用过程发生错误
				cout << "捕获数据包出错" << endl;
				return 0;
			}
			else {  //result=1，捕获成功
				IPPacket = (ARPFrame_t*)pkt_data;  //捕获到的数据包转化为自定义的ARPFrame_t数据包类型
				//判断捕获的IP包是否为之前发的ARP请求的响应包
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP) { 
					cout << "本机网络接口的IP地址与MAC地址对应关系如下：" <<endl;
					//二进制IP转化为字符串
					char address[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &IPPacket->SendIP, address, sizeof(address));
					cout << "IP地址：" << address;
					cout << "   MAC地址： ";
					for (int i = 0; i < 6; i++) {
						if (i < 5)
							printf("%02x:", IPPacket->SendHa[i]);
						else
							printf("%02x", IPPacket->SendHa[i]);
					}
					cout << endl;
					break;
				}
			}
		}
	}

	//向网络发送ARP请求报文，获取其他主机的IP地址和MAC地址的对应关系
	if (IPPacket == NULL) {  
		return 0;
	}
	char ip_address[INET_ADDRSTRLEN];
	cout << "请输入IP地址：";
	cin >> ip_address;
	cout << endl;
	//字符串IP地址转化为二进制网络字节序
	struct sockaddr_in sa;
	inet_pton(AF_INET, ip_address, &(sa.sin_addr));
	RevIP = ARPFrame.RecvIP = sa.sin_addr.s_addr;  //设置为请求IP
	SendIP = ARPFrame.SendIP = IPPacket->SendIP; //设置为主机IP
	for (int i = 0; i < 6; i++) { //设置源MAC地址为主机MAC地址
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMac[i] = IPPacket->SendHa[i];
	}
	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP请求发送失败" << endl;
	}
	else {
		cout << "ARP请求发送成功" << endl;
		while (true) {


			int result = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data); //得到pcap_next_ex的返回结果
			if (result == 0) {  //未捕获到数据包
				cout << "在指定时间范围（read_timeout)内未捕获到数据包" << endl;
				continue;
			}
			else if (result == -1) {  //调用过程发生错误
				cout << "捕获数据包出错" << endl;
				return 0;
			}
			else {  //result=1，捕获成功
				IPPacket = (ARPFrame_t*)pkt_data;  //捕获到的数据包转化为自定义的ARPFrame_t数据包类型
				//判断捕获的IP包是否为之前发的ARP请求的响应包
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP) {
					cout << "输入的IP地址与MAC地址对应关系如下：" << endl;
					//二进制IP转化为字符串
					char address[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &IPPacket->SendIP, address, sizeof(address));
					cout << "IP地址：" << address;
					cout << "   MAC地址： ";
					for (int i = 0; i < 6; i++) {
						if (i < 5)
							printf("%02x:", IPPacket->SendHa[i]);
						else
							printf("%02x", IPPacket->SendHa[i]);
					}
					cout << endl;
					break;
				}
			}
		}
	}
	pcap_close(pcap_handle);  //关闭当前接口
	pcap_freealldevs(alldevs); //释放设备链表
	return 0;
}