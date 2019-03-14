#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <string>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)

using namespace std;

#define DEFAULT_PACKET_SIZE 40
#define DEFAULT_BUFFER_SIZE 1024

#define Err -1
#define EndTracert 2

typedef struct ICMPHeader
{
	unsigned char	Type;
	unsigned char	Code;
	unsigned short	Checksum;
	unsigned short	ID;
	unsigned short	Seq;
} ICMP, *PICMP;

typedef struct IP
{
	unsigned char VersionAndLength;
	unsigned char srv_type;
	unsigned short total_len;
	unsigned short pack_id;
	unsigned short flags : 3;
	unsigned short offset : 13;
	unsigned char TTL;
	unsigned char proto;
	unsigned short checksum;
	unsigned int SourceIp;
	unsigned int DestIp;
} IP, *PIP;

typedef struct Packetinfo 
{
	struct sockaddr_in *src;
	unsigned long ping;
} PacketInfo, *PPacketInfo;

typedef struct _Settings
{
	int hops;
	int delay;
	int packets;
	string Ip;
} Settings;

unsigned short calcCheckSum(unsigned short *packet) {
	unsigned long checksum = 0;
	int size = 40;
	while (size > 1) {
		checksum += *(packet++);
		size -= sizeof(unsigned short);
	}
	if (size) checksum += *(unsigned char *)packet;

	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);

	return (unsigned short)(~checksum);
}

void initPing(PICMP sendHdr, unsigned char seq)
{
	sendHdr->Type = 8;
	sendHdr->Code = 0;
	sendHdr->Checksum = 0;
	sendHdr->ID = 1;
	sendHdr->Seq = seq; //������ ���� ������ ������
	sendHdr->Checksum = calcCheckSum((unsigned short *)sendHdr);
}

int sendPing(SOCKET sock, PICMP sendBuf, const struct sockaddr_in *dst)
{
  //�����, ��������� �� ����� � �������, ������ ������ � �������, ����� ������������ ������ ������ ������, ����� ������ �� ������� ���, ������ ���������
	int Res = sendto(sock, (char *)sendBuf, DEFAULT_PACKET_SIZE, 0, (struct sockaddr *)dst, sizeof(struct sockaddr_in));

	if (Res == SOCKET_ERROR) 
		return Res;
	return 0;
}

int answDecode(PIP ipHdr, struct sockaddr_in *src, unsigned short seq, unsigned long SendTime, PPacketInfo decodeResult)
{
//� ����� ��� �������� ip ����� � ������� ����� ICMP �����
//���� ��� ������ 11 ������ ����� ����� ������� � � ������ ����� 
//����� ���������� ���� ip ������ � ������� ����� ICMP �����
//���� �������� seq ��������� ������ ��� ����� ��� �����

	unsigned long arrivalTime = GetTickCount();
  //����� �������� ��� ������
	unsigned short ipHdrLen = (ipHdr->VersionAndLength & 0x0F) * 4;
  //�������� ������ �� ������������ ������ ��� ICMP �����
	PICMP icmpHdr = (PICMP)((char *)ipHdr + ipHdrLen);

  //���=11 ����� ����� ������ �������
	if (icmpHdr->Type == 11) 
	{
	  //�������� ��������� ip ������
		PIP reqIPHdr = (PIP)((char *)icmpHdr + 8);
	  //�������� ������ �� ������������ ������ ��� ICMP �����
		unsigned short requestIPHdrLen = (reqIPHdr->VersionAndLength & 0x0F) * 4;
      //������� ��� ICMP �����
		PICMP requestICMPHdr = (PICMP)((char *)reqIPHdr + requestIPHdrLen);
	  //���� �������� ������� �� �� ������� ���� �����
		if  (requestICMPHdr->Seq == seq)
		{
			decodeResult->ping = arrivalTime - SendTime;
			decodeResult->src = src;
			return 1;
		}
	}

  //���=0 ��� ���-�����
	if (icmpHdr->Type == 0) 
	{
	  //���� �������� ������� �� �� ������� ���� �����
		if  (icmpHdr->Seq == seq) 
		{
			decodeResult->ping = arrivalTime - SendTime;
			decodeResult->src = src;
			return EndTracert;
		}
	}

	return Err;
}

int recvPing(SOCKET sock, PIP recvBuf, struct sockaddr_in *src, int delay)
{
	int srcLen = sizeof(struct sockaddr_in);
  //��������� ��� ������������ ������ �� ���������� � ������� select
	fd_set singleSocket;
	singleSocket.fd_count = 1;
	singleSocket.fd_array[0] = sock;
  //����� �������� �������� 2 ������� 0 ����������
	struct timeval timeToWait = { delay, 0 };

  //��� ����� 2 �������
  //select ����� ���������� ������� ������� ����� ������ � ���� ������� 0 �� ����� �������� �������
	int selectRes = select(0, &singleSocket, NULL, NULL, &timeToWait);
	if (selectRes == 0)
		return 0;

	if (selectRes == SOCKET_ERROR) 
		return 1;

  //���������� ���������� �������� ����
	return recvfrom(sock, (char *)recvBuf, DEFAULT_BUFFER_SIZE, 0, (struct sockaddr *)src, &srcLen);
}

void print(PPacketInfo info, BOOL printIP)
{
	printf_s("%6d", info->ping);

	if (printIP)
	{
	  //�� IPv4 � ������
		char *srcAddr = inet_ntoa(info->src->sin_addr);
		if (srcAddr != NULL) 
		{
			printf_s("\t%s", srcAddr);
		}
		else
		{
			printf_s("unknown IP");
		}
		char hbuf[NI_MAXHOST];
		if (!getnameinfo((struct sockaddr *)(info->src), sizeof(struct sockaddr_in), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD))
			printf_s(" %s", hbuf);
	}
}

void Hint(Settings *setting)
{
	cout << "��������� ��� ���������\n";

	cout << "�������� �� ���������:\n\tIP = " << setting->Ip << "\n\t���������� ��������� ������� = " << setting->packets << '\n';
	cout << "\t������������ ����� ����� ������ = " << setting->hops << "\n\t����� �������� ������ = " << setting->delay << '\n';
}

void UserInput(Settings *setting)
{
	string answ;
	cout << "�������� ����������� ���������?\n";
	do
	{
		cout << "�����(y/Y, n/N): ";
		getline(cin, answ);
	} while (answ[0] != 'y' && answ[0] != 'n' && answ[0] == 'Y' && answ[0] == 'N');

	if (answ[0] == 'y' || answ[0] == 'Y')
	{
		cout << "������� <Enter> ���� ������ �������� ����������� �������\n";
		cout << "IP = ";
		answ = "";
		getline(cin, answ);
		if (answ.length() != 0)
			setting->Ip = answ;

		cout << "���������� ������� = ";
		answ = "";
		getline(cin, answ);
		if (answ.length() != 0)
			setting->packets = stoi(answ);

		cout << "������������ ����� ����� ������ = ";
		answ = "";
		getline(cin, answ);
		if (answ.length() != 0)
			setting->hops = stoi(answ);

		cout << "����� �������� ������ = ";
		answ = "";
		getline(cin, answ);
		if (answ.length() != 0)
			setting->delay = stoi(answ);
	}
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "Russian");
	
	Settings setting = { 30, 2, 3, "8.8.8.8"};
	
	Hint(&setting);
	UserInput(&setting);
//������������� ����������
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		cout << "error" << endl;
		exit(1);
	}
	
	SOCKADDR_IN dst,src;
	PICMP sendBuf = (PICMP)malloc(DEFAULT_PACKET_SIZE);
	PIP recvBuf = (PIP)malloc(DEFAULT_BUFFER_SIZE);

	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf_s("Socket failed with error %d\n", WSAGetLastError());
		return 1;
	}

	PacketInfo info;
	int ttl = 0;
	int numb = 1;
	unsigned char seq = 0;
	unsigned long SendTime;

	BOOL traceEnd = FALSE, error = FALSE, printIP;

//������������ �� std::string � char*
	char *cstr = new char[setting.Ip.length() + 1];
	strcpy(cstr, setting.Ip.c_str());
//�� ������ � IPv4
	dst.sin_addr.s_addr = inet_addr(cstr);
	dst.sin_family = AF_INET;
	free(cstr);

	system("cls");
	cout << "����������� �������� � " << setting.Ip <<  endl;
	cout << "� ������������ ������ ������� " << setting.hops << ": " << endl;
	do
	{
		setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&(++ttl), sizeof(int));

		printIP = FALSE;
		printf_s("%3d.", numb++);
		
		for (int i = 1; i <= setting.packets; i++) 
		{
		//���� ��� �������� packets ������� �� ����� ������� netbios ���(���� ����)
			if (i == setting.packets)
				printIP = TRUE;
		  //seq ������ ���� ������ ������
			initPing(sendBuf, ++seq);
			SendTime = GetTickCount();
			sendPing(sock, sendBuf, &dst);
			int recvRes = 2;
			int decodeRes = Err;
			
		//�������� ���������� �������� ����
			recvRes = recvPing(sock, recvBuf, &src, setting.delay);
		//���� �������� 0 ���� ������ ����� �������� �������
			if (recvRes == 0) 
			{
				printf_s("\t*");
			}
			else
			{
				decodeRes = answDecode(recvBuf, &src, seq, SendTime, &info);
			}
			
			if (recvRes > 1) 
			{
				if (decodeRes == Err) 
				{
					printf_s("\t*");
				}
				else 
				{
					if (decodeRes == EndTracert) 
					{
						traceEnd = TRUE;
					}
					print(&info, printIP);
				}
			}
		}
		printf_s("\n");
	} while (!traceEnd && (ttl != setting.hops));
		system("pause");
}