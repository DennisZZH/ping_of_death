// PoD Attacker
// Author: Zihao Zhang
// Date: 4.18.2020

#include <iostream>
#include <cstdlib>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <errno.h>
#include <netinet/ip_icmp.h>

#define PING_PKT_SIZE 64

using namespace std;

char* server_ip = "128.111.48.196";
int port = 43141;

char* icmp_src = "192.168.222.1";
char* icmp_dst = "192.168.222.2";


// ping packet structure 
struct ping_pkt 
{ 
    struct icmphdr hdr; 
    char msg[PING_PKT_SIZE - sizeof(struct icmphdr)]; 
};


// Calculating the Check Sum 
unsigned short checksum(void *b, int len) 
{   
    unsigned short *buf = (unsigned short*) b; 
    unsigned int sum=0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 


int main(){

    uint16_t msg_siz = 0;
    char msg_buf[1500];
    char siz_buf[2];
    string msg_str;
    int siz_read = 0, to_read = 0;
    char* bufptr;

    // Open TCP connection
    struct sockaddr_in server_address;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("Socket creation failed.\n");
        exit(0);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(server_ip);
    server_address.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr*)&server_address, sizeof(server_address)) != 0) {
        printf("Error number: %d\n", errno);
        printf("The error message is %s\n", strerror(errno));
        printf("Connection with the server failed.\n");
        exit(0);
    }

    cout<<"Start tasks!"<<endl;

    // Prepare a ICMP packet
    struct ping_pkt pckt;
    int msg_count = 0;
    bzero(&pckt, sizeof(pckt));
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = getpid();

    for(int i = 0; i < sizeof(pckt.msg) - 1; i++){
        pckt.msg[i] = i + '0';
    }
    pckt.msg[sizeof(pckt.msg)] = 0;

    pckt.hdr.un.echo.sequence = msg_count++;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    cout<<"Send Pckt!"<<endl;

    // Send packet to server
    msg_siz = htons((uint16_t) sizeof(pckt));
    memcpy(siz_buf, &msg_siz , 2);

    if(send(sockfd, siz_buf, sizeof(siz_buf), 0) < 0){
        cerr<<"Failed to send the size."<<endl;
        exit(0);
    }

    if(send(sockfd, &pckt, sizeof(pckt), 0) < 0){
        cerr<<"Failed to send the body."<<endl;
        exit(0);
    }

    cout<<"Receive Pckt!"<<endl;

    // Receive packet from server
    cout<<"recv size"<<endl;
    bufptr = (char*) siz_buf;
    to_read = sizeof(siz_buf);
    while(to_read > 0){
        siz_read = recv(sockfd, bufptr, to_read, 0);
        if(siz_read < 0){
            cerr<<"Failed to recv the size."<<endl;
            exit(0);
        }
        to_read -= siz_read;
        bufptr += siz_read;
    }
    memcpy(&msg_siz, siz_buf, 2);
    msg_siz =ntohs(msg_siz);

    cout<<"recv body"<<endl;
    bufptr = (char*) msg_buf;
    to_read = msg_siz;
    while(to_read > 0){
        siz_read = recv(sockfd, bufptr, to_read, 0);
        if(siz_read < 0){
            cerr<<"Failed to recv the body."<<endl;
            exit(0);
        }
        to_read -= siz_read;
        bufptr += siz_read;
    }
    memcpy(&pckt, msg_buf, msg_siz);



    close(sockfd);

    return 0;
}