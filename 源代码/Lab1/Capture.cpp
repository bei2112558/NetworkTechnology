#include<iostream>
#include<stdio.h>
#include "pcap.h"   //添加pca.h包含文件
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
using namespace std;

#pragma pack(1) //以1字节对齐

typedef struct FrameHeader_t {  //数据帧首部
	BYTE DesMac[6]; //目的地址
	BYTE SrcMac[6]; //源地址
	WORD FrameType; //帧类型
}FrameHeader_t;

typedef struct IPHeader_t {  //IP首部
	BYTE Ver_HLen;  // 版本和首部包头长度 ，分别占4比特
	BYTE Tos; //服务类型
	WORD TotalLen;  //总长度
	WORD ID;   //标识
	WORD Flag_Segment; //标志
	BYTE TTL;     //生存周期
	BYTE Protocol;   //协议
	WORD Checksum;  //头部校验和
	ULONG SrcIP;   //源IP地址
	ULONG DstIP;   //目的IP地址
}IPHeader_t;

typedef struct Data_t {  //包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

#pragma pack()  //恢复默认对齐方式

void Capture() {
	pcap_if_t* alldevs;  //指向设备链表首部的指针
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
	pcap_if_t* CurrentDevics;  //表示当前读取的网络接口设备

	//调用PCAP自带的pcap_findalldevs_ex函数，获得网络接口设备链表地址，并赋值给alldevs指针
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		cout << "获取设备列表失败" << endl;  //获取网络接口列表失败，结束程序
		return;
	}
	
	//读取所有网络接口卡设备的数据包
	for (CurrentDevics=alldevs; CurrentDevics != NULL;CurrentDevics=CurrentDevics->next) {
		cout << "当前网络设备接口卡名字为：" << CurrentDevics->name << endl;
		//打开网络接口
		//指定获取数据包最大长度为65536,比所能遇到的最大的MTU还大的数字，可以确保程序可以抓到整个数据包
		//指定时间范围为300
		pcap_t* p = pcap_open(CurrentDevics->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 500, NULL, errbuf);
		if (p == NULL) {
			cout<< "打开当前网络接口失败"<<endl;  //打开当前网络接口失败，继续下一个接口
			continue;
		}

		while (1) { 		//在打开的网络接口卡上捕获其所有的网络数据包
			struct pcap_pkthdr* pkt_header;//保存了捕获数据包的基本信息，比如捕获的时间戳、数据包的长度等
			const u_char* pkt_data;  //指向捕获到的数据包

			int result = pcap_next_ex(p, &pkt_header, &pkt_data); //得到pcap_next_ex的返回结果
			if (result == 0) {  //未捕获到数据包
				cout<<"在指定时间范围（read_timeout)内未捕获到数据包"<<endl;
				continue;
			}
			else if (result == -1) {  //调用过程发生错误
				cout<<"捕获数据包出错"<<endl;
				break;
			}
			else {  //result=1，捕获成功
				Data_t* IPPacket = (Data_t*)pkt_data;  //捕获到的数据包转化为自定义的Data_t数据包类型
				cout<<"目的Mac地址为: ";
				for (int i = 0; i < 6; i++) {//由于DesMac类型为byte，将其转化为16进制
					printf("%02x", IPPacket->FrameHeader.DesMac[i]); // "02x"表示至少输出两位16进制字符，不足位补0
				}
				cout<<"  源Mac地址为: ";  //输出源Mac地址
				for (int i = 0; i < 6; i++) {
					printf("%02x", IPPacket->FrameHeader.SrcMac[i]);
				}
				cout<<"  类型/长度为： ";  //FrameType为WORD类型，由于网络序和主机序不同，进行转化
				printf("%02x", ntohs(IPPacket->FrameHeader.FrameType)); //ntohs将16位整数网络序转化为主机序
				cout<<"H"<<endl;
			}
		}
		pcap_close(p);  //关闭当前接口
	}
	pcap_freealldevs(alldevs); //释放网络接口设备列表
}

int main() {
	Capture();
	return 0;
}
