#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <float.h>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <deque>
#include <map> 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <linux/types.h>
#include <fcntl.h>
#include <boost/foreach.hpp>
#include "uint256.h"
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <errno.h>
#define printf(...) fprintf (stdout, __VA_ARGS__); fflush(stdout);

using namespace std;
unsigned int pnSeed[] = { 0x58cea445, 0x2b562f4e, 0x291f20b2, 0 };
uint256 hashNameCoinGenesisBlock("000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770");
unsigned const char header[4]={0xF9,0xBE,0xB4,0xFE};

int bigToLittleEndian(int big)
{
return (big &255)<<24 | (big & (255<<8))<<8 | (big & (255 <<16))>>8 | (big & (255<<24))>>24;
}

int littleToBigEndian(int little)
{
return (little &255)<<24 | (little & (255<<8))<<8 | (little & (255 <<16))>>8 | (little & (255<<24))>>24;
}
void error(const char *msg)
{
    perror(msg);
    exit(0);
}
template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}
int main(int argc, char *argv[])
{
unsigned char command[12]={0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,0x00,0x00,0x00,0x00,0x00};
unsigned char length[4]={0x55,0x00,0x00,0x00};
// unsigned char buff[100];
// bzero(buff,sizeof(buff));
// unsigned char shaTest[SHA256_DIGEST_LENGTH];
// int fdTest=open("../../testFoo2.bin",O_RDONLY);
// int bytesread=read(fdTest,buff,100);
// if(bytesread<0)
// {
// printf("problem\n");
// return 0;
// }
// printf("first Byte is:%02X\n",buff[0]);
// int checksumTest=0;
// // uint256 hashTest=Hash(&buff[0],&buff[99]);
// // memcpy(&checksumTest,&hashTest,4);
// SHA256((unsigned char*)&buff,sizeof(buff),(unsigned char*)&shaTest);
// SHA256((unsigned char*)&shaTest,sizeof(shaTest),(unsigned char*)&shaTest);
// memcpy(&checksumTest,&shaTest,4);
// checksumTest=htonl(checksumTest);
// printf("hash is:%02X\n",checksumTest);
// return 0;

unsigned char version[4]= {0xB8,0x88,0x00,0x00};
unsigned char service[8]={0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
int now=bigToLittleEndian(time(0));
int recAddr=littleToBigEndian(pnSeed[1]);
int myadd=184<<24|18<<16|120<<8|224;
unsigned char dst[4]={(recAddr&255<<24)>>24,(recAddr&255<<16)>>16,(recAddr&255<<8)>>8,recAddr&255};
unsigned char date[8]={(now & (255<<24))>>24,(now & (255<<16))>>16,(now & (255<<8))>>8,(now & (255)),0x00,0x00,0x00,0x00};
//unsigned char destIP[26]={0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,(recAddr&255<<24)>>24,(recAddr&255<<16)>>16,(recAddr&255<<8)>>8,recAddr&255,0x20,0xb0};
unsigned char destIP[26]={0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,91,121,174,223,0x20,0x8e};
unsigned char sourceIP[26]={0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,184,18,120,224,0x20,0x8e};
unsigned char nodeID[8]={0xCA,0x81,0xCD,0x73,0xA6,0xCF,0xDC,0x8F};
unsigned char subVersion[1]={0x00};
unsigned char lastIndex[4]={0x00,0x00,0x00,0x00};
unsigned char message[85];
memcpy(&message[0],version,4);
memcpy(&message[4],service,8);
memcpy(&message[12],date,8);
memcpy(&message[20],destIP,26);
memcpy(&message[46],sourceIP,26);
memcpy(&message[72],nodeID,8);
memcpy(&message[80],subVersion,1);
memcpy(&message[81],lastIndex,4);
unsigned char sha[SHA256_DIGEST_LENGTH];
SHA256((unsigned char*)&message,sizeof(message),(unsigned char*)&sha);
SHA256((unsigned char*)&sha,sizeof(sha),(unsigned char*)&sha);
//uint256 foo=Hash(&message[0],&message[84]);
unsigned char checksum[4];
int check=0;
memcpy(&check,&sha,4);
//check=htonl(check);
printf("hash is:%02X\n",check);

memcpy(&checksum,&check,4);
int sockfd, portno, n;
sockfd = socket(AF_INET, SOCK_STREAM, 0);
portno=8334;
struct sockaddr_in ip4addr;

ip4addr.sin_family = AF_INET;
ip4addr.sin_port = htons(8334);
printf("connecting to %s","91.121.174.223");
inet_pton(AF_INET, "91.121.174.223", &ip4addr.sin_addr);

sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
int fd=open("./foo.bin",O_WRONLY|O_CREAT);
 if (connect(sockfd,(struct sockaddr*)&ip4addr,sizeof(ip4addr)) < 0) 
 {
        error("ERROR connecting");
}
 
unsigned char fullmsg[109];
memcpy(&fullmsg[0],header,4);
memcpy(&fullmsg[4],command,12);
memcpy(&fullmsg[16],length,4);
memcpy(&fullmsg[20],checksum,4);
memcpy(&fullmsg[24],message,85);
n = write(sockfd,fullmsg,109);
if(n<0)
{
error("ERROR writing to socket");
}
char buffer[1]={0x00};
printf("ok got all that stuff\nmoving on\n");
n = read(sockfd, buffer, 1);
printf("stuff\n");
printf("%02X",buffer[0]);
bzero(buffer,1);
printf("\n");
return 0;
close(sockfd);
for(int i = 0; i<26; i++)
     printf("%02X", sourceIP[i]);
printf("\n");
return 0;
}