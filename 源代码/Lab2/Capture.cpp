#include<iostream>
#include "winsock2.h"
#include "pcap.h"   //���pca.h�����ļ�
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
using namespace std;

#pragma pack(1) //��1�ֽڶ���
typedef struct FrameHeader_t {  //������̫��֡�ײ�
	BYTE DesMac[6]; //Ŀ�ĵ�ַ
	BYTE SrcMac[6]; //Դ��ַ
	WORD FrameType; //֡����
}FrameHeader_t;

typedef struct ARPFrame_t {//ARP֡
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
}ARPFrame_t;

#pragma pack()  //�ָ�Ĭ�϶��뷽ʽ

int main() {
	pcap_if_t* alldevs; //ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];  //������Ϣ������
	ARPFrame_t ARPFrame;
	DWORD SendIP;
	DWORD RevIP;
	struct pcap_pkthdr* pkt_header;//�����˲������ݰ��Ļ�����Ϣ�����粶���ʱ��������ݰ��ĳ��ȵ�
	const u_char* pkt_data;  //ָ�򲶻񵽵����ݰ�
	ARPFrame_t* IPPacket=NULL; //���񵽵�ARP��Ӧ��

	//��ȡ��������ӿ��豸����
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		cout<< "��ȡ�豸�б�ʧ��" << endl;  //��ȡ����ӿ��б�ʧ�ܣ���������
		return 0;
	}
	int i = 0;
	for (d = alldevs; d != NULL; d = d->next) { //�����豸������ʾIP
		//��ȡ��ǰ����ӿ��豸��IP��ַ��Ϣ
		i++;
		cout << "���� " << i << " " << d->name << endl;
		cout<<"������Ϣ��" << d->description <<endl;
		for (a = d->addresses; a != NULL; a = a->next) {
			if ((a->addr->sa_family == AF_INET)) {  //�жϸõ�ַ�Ƿ�ΪIP��ַ
				//��a->addrת��Ϊsockaddr_in���ͻ�ȡ�����ֽ����IP��ַ��inet_ntop����ת��Ϊ���ʮ���Ƶ�IP
				char address[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(((struct sockaddr_in*)a->addr)->sin_addr), address, sizeof(address));
				cout << "IP��ַ��" << address<< endl;
				inet_ntop(AF_INET, &(((struct sockaddr_in*)a->netmask)->sin_addr), address, sizeof(address));
				cout << "�������룺" << address << endl;
			}
		}
		cout << endl;
	}
	//����Ӧ������
	int id;
	cout << "��ѡ��������";
	cin >>id;
	cout << endl;
	d = alldevs;
	for (int i = 1; i < id; i++) {
		d = d->next;
		if (d == NULL) {
			cout << "��������������" << endl;
			return 0;
		}
	}

	//������
	pcap_t* pcap_handle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (pcap_handle == NULL) {
		cout << "������ʧ��" << endl;
		return 0;
	}
	//���ù��˹��򣬹���ARP��
	u_int netmask;
	netmask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program fcode;  //��ű����Ĺ���
	char packet_filter[] = "ether proto \\arp";//���˹���ether��ʾ��̫��ͷ������̫��ͷ��proto�ֶ�ֵΪ0x0806����ARP
	if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) < 0) 
	{
		cout << "�޷��������ݰ�������������﷨";
		pcap_freealldevs(alldevs);
		return 0;
	}
	//���ù�����
	if (pcap_setfilter(pcap_handle, &fcode) < 0)
	{
		cout << "���������ô���";
		pcap_freealldevs(alldevs);
		return 0;
	}

	//��װ����
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMac[i] = 0xFF;//����Ϊ�����㲥��ַ255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMac[i] = 0x66;//����Ϊ�����MAC��ַ66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;//����Ϊ0����Ϊ��ʱ��Ӳ��Ŀ��MAC��ַ��δȷ��
		ARPFrame.SendHa[i] = 0x66; //����Ϊ��ٵ�MAC��ַ66-66-66-66-66-66
	} 
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4; // Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	SendIP = ARPFrame.SendIP = htonl(0x70707070);//ԴIP��ַ����Ϊ�����IP��ַ 112.112.112.112
	//����ѡ���������IP����Ϊ�����IP��ַ
	for (a = d->addresses; a != NULL; a = a->next){
		if (a->addr->sa_family == AF_INET){
			RevIP = ARPFrame.RecvIP = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
		}
	}
	//ģ��Զ��������ARP���󣬲��񱾻���ARP��Ӧ����ȡ��������ӿ�MAC��ַ
	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP������ʧ��" << endl;
	}
	else {
		cout << "ARP�����ͳɹ�" << endl;
		while (true) {
			

			int result = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data); //�õ�pcap_next_ex�ķ��ؽ��
			if (result == 0) {  //δ�������ݰ�
				cout << "��ָ��ʱ�䷶Χ��read_timeout)��δ�������ݰ�" << endl;
				continue;
			}
			else if (result == -1) {  //���ù��̷�������
				cout << "�������ݰ�����" << endl;
				return 0;
			}
			else {  //result=1������ɹ�
				IPPacket = (ARPFrame_t*)pkt_data;  //���񵽵����ݰ�ת��Ϊ�Զ����ARPFrame_t���ݰ�����
				//�жϲ����IP���Ƿ�Ϊ֮ǰ����ARP�������Ӧ��
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP) { 
					cout << "��������ӿڵ�IP��ַ��MAC��ַ��Ӧ��ϵ���£�" <<endl;
					//������IPת��Ϊ�ַ���
					char address[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &IPPacket->SendIP, address, sizeof(address));
					cout << "IP��ַ��" << address;
					cout << "   MAC��ַ�� ";
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

	//�����緢��ARP�����ģ���ȡ����������IP��ַ��MAC��ַ�Ķ�Ӧ��ϵ
	if (IPPacket == NULL) {  
		return 0;
	}
	char ip_address[INET_ADDRSTRLEN];
	cout << "������IP��ַ��";
	cin >> ip_address;
	cout << endl;
	//�ַ���IP��ַת��Ϊ�����������ֽ���
	struct sockaddr_in sa;
	inet_pton(AF_INET, ip_address, &(sa.sin_addr));
	RevIP = ARPFrame.RecvIP = sa.sin_addr.s_addr;  //����Ϊ����IP
	SendIP = ARPFrame.SendIP = IPPacket->SendIP; //����Ϊ����IP
	for (int i = 0; i < 6; i++) { //����ԴMAC��ַΪ����MAC��ַ
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMac[i] = IPPacket->SendHa[i];
	}
	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP������ʧ��" << endl;
	}
	else {
		cout << "ARP�����ͳɹ�" << endl;
		while (true) {


			int result = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data); //�õ�pcap_next_ex�ķ��ؽ��
			if (result == 0) {  //δ�������ݰ�
				cout << "��ָ��ʱ�䷶Χ��read_timeout)��δ�������ݰ�" << endl;
				continue;
			}
			else if (result == -1) {  //���ù��̷�������
				cout << "�������ݰ�����" << endl;
				return 0;
			}
			else {  //result=1������ɹ�
				IPPacket = (ARPFrame_t*)pkt_data;  //���񵽵����ݰ�ת��Ϊ�Զ����ARPFrame_t���ݰ�����
				//�жϲ����IP���Ƿ�Ϊ֮ǰ����ARP�������Ӧ��
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP) {
					cout << "�����IP��ַ��MAC��ַ��Ӧ��ϵ���£�" << endl;
					//������IPת��Ϊ�ַ���
					char address[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &IPPacket->SendIP, address, sizeof(address));
					cout << "IP��ַ��" << address;
					cout << "   MAC��ַ�� ";
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
	pcap_close(pcap_handle);  //�رյ�ǰ�ӿ�
	pcap_freealldevs(alldevs); //�ͷ��豸����
	return 0;
}