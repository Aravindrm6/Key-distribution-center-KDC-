
#include <string.h> //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include "miracl.h"
#include <time.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#define MAX 80
#define PORT 8081
#define BOBPORT 8085
#define SA struct sockaddr
#define ID 0
#define BOBID 1

void send_to(int sockfd, char *buff)
{
    write(sockfd, buff, sizeof(buff));
}

void genString(char *string, int len) // len only supprt multiples of two
{
    big digit = mirvar(0);
    int max, out;
    long seed = 12348452;
    irand(clock());
    char ptr[20];
    bigdig(20, 20, digit);
    len /= 2;
    out = big_to_bytes(20, digit, ptr, 0);
    for (int i = 0; i < 2; i++)
        sprintf(&string[i * 2], "%02x", (unsigned char)ptr[i]);
}

void encrypt(char *msg, char *key) // same for encrypt and decrypt
{
    int len = strlen(key);
    int i;
    for (i = 0; msg[i]; i++)
        msg[i] = msg[i] ^ key[i % len];
}

void decrypt(char *msg, char *key, int size)
{
    int len = strlen(key);
    int i = 0;
    for (; i <= size; i++)
        msg[i] = msg[i] ^ key[i % len];
}

int genNounce() // return 6 digit nounce
{

    big digit = mirvar(0);
    int max, out;
    char num[6];
    long seed = 12348452;
    irand(clock());
    char ptr[20];
    bigdig(5, 15, digit);
    cotstr(digit, num);
    int i = strlen(num);
    while (i < 6)
        num[i++] = '0';
    return atoi(num);
}
void getNounceString(int nounce, char *sNounce)
{
    int i = 5;
    while (nounce)
    {
        int t = nounce % 10;
        nounce = nounce / 10;
        sNounce[i--] = t + '0';
    }
}

char *initial_key_exchange(char *buff)
{
    int sockfd, connfd;
    char *t = "INIT0";
    struct sockaddr_in servaddr, cli;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);
    if (connect(sockfd, (SA *)&servaddr, sizeof(servaddr)) != 0)
    {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the KDC..\nInitial Key Exchange started.....\n");
    send_to(sockfd, t);
    read(sockfd, buff, sizeof(buff));
    buff[8] = '\0';
    close(sockfd);
    return buff;
}

int get_connection(char *host, int port)
{
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("socket creation failed...\n");
        exit(0);
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(host);
    servaddr.sin_port = htons(port);
    if (connect(sockfd, (SA *)&servaddr, sizeof(servaddr)) != 0)
    {
        printf("connection with the server failed...\n");
        exit(0);
    }
    return sockfd;
}
void parse_kdc_response(char *buff, char *session_key)
{
    for (int i = 7; i <= 14; i++)
        session_key[i - 7] = buff[i];
}
int main()
{
    miracl *mip = mirsys(5000, 10);
    char key[16];
    char session_key[16];
    long nounce;
    char *sNounce[6];
    long bob_nounce;
    char *bob_nounce_string[6];
    char buff[80];
    char msg[100];
    char ticket[16];
    initial_key_exchange(key);
    nounce = genNounce();
    msg[0] = ID + '0';
    msg[1] = BOBID + '0';
    getNounceString(nounce, sNounce);
    strcat(msg, sNounce);
    printf("\nGot key from server %s\nNounce generated at Alice : %s.\n\nFirst msg to server(ALICEid+BOBid+Nounce): %s\n", key, sNounce, msg);

    ////////////////serverstuff
    int sockfd = get_connection("127.0.0.1", PORT);
    send_to(sockfd, msg);
    bzero(buff, 80);
    bzero(ticket, 16);
    read(sockfd, buff, sizeof(buff)); // getting first msg with ticket
    read(sockfd, ticket, 9);
    printf("\nDecrypting server response from key %s\n", key);
    decrypt(buff, key, 14);
    parse_kdc_response(buff, session_key);
    printf("\nAfter decrypt things from KDC(nounce+bobid+session+TicketToBoB(encrypted with BOB's key)) %s  %d\n", buff, strlen(buff));
    printf("\nSession key : %s\n", session_key);

    printf("\nSending ticket to BOB\n");
    int bob_sockfd = get_connection("127.0.0.1", BOBPORT);
    send_to(bob_sockfd, ticket);
    bzero(bob_nounce_string, 6);
    read(bob_sockfd, bob_nounce_string, 6);
    decrypt(bob_nounce_string, session_key, 5);
    printf("\nGot nounce from BOB.\nDecrypted(with session key) %s", bob_nounce_string);
    bob_nounce = atoi(bob_nounce_string);
    bob_nounce -= 1;
    bzero(bob_nounce_string, 6);
    getNounceString(bob_nounce, bob_nounce_string);
    printf("\nSending back to BOB %s\n", bob_nounce_string);
    encrypt(bob_nounce_string, session_key);
    send_to(bob_sockfd, bob_nounce_string);
    close(bob_sockfd);
    close(sockfd);
}