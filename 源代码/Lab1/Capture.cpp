#include<iostream>
#include<stdio.h>
#include "pcap.h"   //���pca.h�����ļ�
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
using namespace std;

#pragma pack(1) //��1�ֽڶ���

typedef struct FrameHeader_t {  //����֡�ײ�
	BYTE DesMac[6]; //Ŀ�ĵ�ַ
	BYTE SrcMac[6]; //Դ��ַ
	WORD FrameType; //֡����
}FrameHeader_t;

typedef struct IPHeader_t {  //IP�ײ�
	BYTE Ver_HLen;  // �汾���ײ���ͷ���� ���ֱ�ռ4����
	BYTE Tos; //��������
	WORD TotalLen;  //�ܳ���
	WORD ID;   //��ʶ
	WORD Flag_Segment; //��־
	BYTE TTL;     //��������
	BYTE Protocol;   //Э��
	WORD Checksum;  //ͷ��У���
	ULONG SrcIP;   //ԴIP��ַ
	ULONG DstIP;   //Ŀ��IP��ַ
}IPHeader_t;

typedef struct Data_t {  //����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

#pragma pack()  //�ָ�Ĭ�϶��뷽ʽ

void Capture() {
	pcap_if_t* alldevs;  //ָ���豸�����ײ���ָ��
	char errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������
	pcap_if_t* CurrentDevics;  //��ʾ��ǰ��ȡ������ӿ��豸

	//����PCAP�Դ���pcap_findalldevs_ex�������������ӿ��豸�����ַ������ֵ��alldevsָ��
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		cout << "��ȡ�豸�б�ʧ��" << endl;  //��ȡ����ӿ��б�ʧ�ܣ���������
		return;
	}
	
	//��ȡ��������ӿڿ��豸�����ݰ�
	for (CurrentDevics=alldevs; CurrentDevics != NULL;CurrentDevics=CurrentDevics->next) {
		cout << "��ǰ�����豸�ӿڿ�����Ϊ��" << CurrentDevics->name << endl;
		//������ӿ�
		//ָ����ȡ���ݰ���󳤶�Ϊ65536,����������������MTU��������֣�����ȷ���������ץ���������ݰ�
		//ָ��ʱ�䷶ΧΪ300
		pcap_t* p = pcap_open(CurrentDevics->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 500, NULL, errbuf);
		if (p == NULL) {
			cout<< "�򿪵�ǰ����ӿ�ʧ��"<<endl;  //�򿪵�ǰ����ӿ�ʧ�ܣ�������һ���ӿ�
			continue;
		}

		while (1) { 		//�ڴ򿪵�����ӿڿ��ϲ��������е��������ݰ�
			struct pcap_pkthdr* pkt_header;//�����˲������ݰ��Ļ�����Ϣ�����粶���ʱ��������ݰ��ĳ��ȵ�
			const u_char* pkt_data;  //ָ�򲶻񵽵����ݰ�

			int result = pcap_next_ex(p, &pkt_header, &pkt_data); //�õ�pcap_next_ex�ķ��ؽ��
			if (result == 0) {  //δ�������ݰ�
				cout<<"��ָ��ʱ�䷶Χ��read_timeout)��δ�������ݰ�"<<endl;
				continue;
			}
			else if (result == -1) {  //���ù��̷�������
				cout<<"�������ݰ�����"<<endl;
				break;
			}
			else {  //result=1������ɹ�
				Data_t* IPPacket = (Data_t*)pkt_data;  //���񵽵����ݰ�ת��Ϊ�Զ����Data_t���ݰ�����
				cout<<"Ŀ��Mac��ַΪ: ";
				for (int i = 0; i < 6; i++) {//����DesMac����Ϊbyte������ת��Ϊ16����
					printf("%02x", IPPacket->FrameHeader.DesMac[i]); // "02x"��ʾ���������λ16�����ַ�������λ��0
				}
				cout<<"  ԴMac��ַΪ: ";  //���ԴMac��ַ
				for (int i = 0; i < 6; i++) {
					printf("%02x", IPPacket->FrameHeader.SrcMac[i]);
				}
				cout<<"  ����/����Ϊ�� ";  //FrameTypeΪWORD���ͣ������������������ͬ������ת��
				printf("%02x", ntohs(IPPacket->FrameHeader.FrameType)); //ntohs��16λ����������ת��Ϊ������
				cout<<"H"<<endl;
			}
		}
		pcap_close(p);  //�رյ�ǰ�ӿ�
	}
	pcap_freealldevs(alldevs); //�ͷ�����ӿ��豸�б�
}

int main() {
	Capture();
	return 0;
}
