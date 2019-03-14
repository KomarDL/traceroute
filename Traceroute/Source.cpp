#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")
using namespace std;
#define DEFAULT_PACKET_SIZE 40
#define DEFAULT_BUFFER_SIZE 1024
#define _WINSOCK_DEPRECATED_NO_WARNINGS_

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

void initPingPacket(PICMP sendHdr, unsigned char seq)
{
	sendHdr->Type = 8;
	sendHdr->Code = 0;
	sendHdr->Checksum = 0;
	sendHdr->ID = 1;
	sendHdr->Seq = seq; //должен быть всегда разный
	sendHdr->Checksum = calcCheckSum((unsigned short *)sendHdr);
}

int sendPingReq(SOCKET sock, PICMP sendBuf, const struct sockaddr_in *dst)
{
  //сокет, указатель на буфер с данными, размер буфера с данными, флаги определяющие способ выполн вызова, адрес сокета на который шлём, размер структуры
	int Res = sendto(sock, (char *)sendBuf, DEFAULT_PACKET_SIZE, 0, (struct sockaddr *)dst, sizeof(struct sockaddr_in));

	if (Res == SOCKET_ERROR) 
		return Res;
	return 0;
}

int decodeReply(PIP ipHdr, struct sockaddr_in *src, unsigned short seq, unsigned long SendTime, PPacketInfo decodeResult)
{
//в ответ нам приходит ip пакет в котором лежит ICMP пакет
//если тип пакета 11 значит время жизни истекло и в пакете лежит 
//копия посланного нами ip пакета в котором лежит ICMP пакет
//если значения seq совпадают значит это точно наш пакет

	unsigned long arrivalTime = GetTickCount();
  //узнаём смещение для данных
	unsigned short ipHdrLen = (ipHdr->VersionAndLength & 0x0F) * 4;
  //получаем данные по вычисленному адресу это ICMP пакет
	PICMP icmpHdr = (PICMP)((char *)ipHdr + ipHdrLen);

  //Тип=11 время жизни пакета истекло
	if (icmpHdr->Type == 11) 
	{
	  //получаем заголовок ip пакета
		PIP reqIPHdr = (PIP)((char *)icmpHdr + 8);
	  //получаем данные по вычисленному адресу это ICMP пакет
		unsigned short requestIPHdrLen = (reqIPHdr->VersionAndLength & 0x0F) * 4;
      //находим наш ICMP пакет
		PICMP requestICMPHdr = (PICMP)((char *)reqIPHdr + requestIPHdrLen);
	  //если значения совпали то мы словили свой пакет
		if  (requestICMPHdr->Seq == seq)
		{
			decodeResult->ping = arrivalTime - SendTime;
			decodeResult->src = src;
			return 1;
		}
	}

  //Тип=0 это эхо-ответ
	if (icmpHdr->Type == 0) 
	{
	  //если значения совпали то мы словили свой пакет
		if  (icmpHdr->Seq == seq) 
		{
			decodeResult->ping = arrivalTime - SendTime;
			decodeResult->src = src;
			return 2;
		}
	}

	return -1;
}

int recvPing(SOCKET sock, PIP recvBuf, struct sockaddr_in *src)
{
	int srcLen = sizeof(struct sockaddr_in);
  //структура для тестирования сокета на читаемость с помощью select
	fd_set singleSocket;
	singleSocket.fd_count = 1;
	singleSocket.fd_array[0] = sock;
  //задаём интервал ожидания 2 секунды 0 милисекунд
	struct timeval timeToWait = { 2, 0 };

  //ждём ответ 2 секунды
  //select вернёт количество сокетов которые можно читать и если вернуло 0 то время ожидания истекло
	int selectRes = select(0, &singleSocket, NULL, NULL, &timeToWait);
	if (selectRes == 0)
		return 0;

	if (selectRes == SOCKET_ERROR) 
		return 1;

  //возвращает количество принятых байт
	return recvfrom(sock, (char *)recvBuf, DEFAULT_BUFFER_SIZE, 0, (struct sockaddr *)src, &srcLen);
}

void print(PPacketInfo info, BOOL printIP)
{
	printf("%6d", info->ping);

	if (printIP)
	{
	  //из IPv4 в строку
		char *srcAddr = inet_ntoa(info->src->sin_addr);
		if (srcAddr != NULL) 
		{
			printf("\t%s", srcAddr);
		}
		else
		{
			printf("unknown IP");
		}
		char hbuf[NI_MAXHOST];
		if (!getnameinfo((struct sockaddr *)(info->src), sizeof(struct sockaddr_in), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD))
			printf(" %s", hbuf);
	}
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "Russian");
 
//инициализация библиотеки
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cout << "error" << std::endl;
		exit(1);
	}
	
	SOCKADDR_IN dst,src;
	PICMP sendBuf = (PICMP)malloc(DEFAULT_PACKET_SIZE);
	PIP recvBuf = (PIP)malloc(DEFAULT_BUFFER_SIZE);

	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		wprintf(L"socket failed with error %d\n", WSAGetLastError());
		return 1;
	}

	PacketInfo info;
	int ttl = 0;
	int number = 1;
	unsigned char seq = 0;
	unsigned long SendTime;

	int hops = 30;
	BOOL traceEnd = FALSE, error = FALSE, printIP;

//из строки в IPv4
	dst.sin_addr.s_addr = inet_addr("8.8.8.8"/*argv[1]*/);
	dst.sin_family = AF_INET;

	cout << "Трассировка маршрута к " << "8.8.8.8"/*argv[1]*/ <<  endl;
	cout << "с максимальным числом прыжков 30:" << endl;
	do
	{
		setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&(++ttl), sizeof(int));

		printIP = FALSE;
		printf("%3d.", number++);
		
		for (int i = 1; i <= 3; i++) 
		{
		//если уже получили 3 пакета то можно вывести netbios имя(если есть)
			if (i == 3)
				printIP = TRUE;
		  //seq должен быть всегда разный
			initPingPacket(sendBuf, ++seq);
			SendTime = GetTickCount();
			sendPingReq(sock, sendBuf, &dst);
			int recvRes = 2;
			int decodeRes = -1; // ошибка
			
		//получаем количество принятых байт
			recvRes = recvPing(sock, recvBuf, &src);
		//если получено 0 байт значит время ожидания истекло
			if (recvRes == 0) 
			{
				printf("\t*");
			}
			else
			{
				decodeRes = decodeReply(recvBuf, &src, seq, SendTime, &info);
			}
			
			if (recvRes > 1) 
			{
				if (decodeRes == -1) 
				{
					printf("\t*");
				}
				else 
				{
					if (decodeRes == 2) 
					{
						traceEnd = TRUE;
					}
					print(&info, printIP);
				}
			}
		}
		printf("\n");
	} while (!traceEnd && (ttl != hops));
		system("pause");
}