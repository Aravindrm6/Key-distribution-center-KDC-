#include "miracl.h"
#include <time.h>
#include <netdb.h>
#include <stdio.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#define MAX 80
#define KDCPORT 8081
#define BOBPORT 8085
#define SA struct sockaddr
#define ALICE 0
#define BOB 1

void encrypt(char *msg, char *key) // same for encrypt and decrypt
{
    int len = strlen(key);
    int i;
    for (i = 0; msg[i]; i++)
        msg[i] = msg[i] ^ key[i % len];
}

void send_to(int sockfd, char *buff)
{
    //char buff[MAX];
    write(sockfd, buff, sizeof(buff));
    // bzero(buff, sizeof(buff));
}
void decrypt(char *msg, char *key, int size) // same for encrypt and decrypt
{
    int len = strlen(key);
    int i = 0;
    for (; i < size; i++)
        msg[i] = msg[i] ^ key[i % len];
}

void genString(char *string, int len) // len only supprt multiples of two
{
    big digit = mirvar(0);
    int max, out;
    long seed = 12348452;
    irand(clock());
    char ptr[20];
    bigdig(20, 20, digit);
    out = big_to_bytes(20, digit, ptr, FALSE);
    for (int i = 0; i < len / 2; i++)
        sprintf(&string[i * 2], "%02x", (unsigned char)ptr[i]);
}
char *initial_key_exchange(char *buff)
{
    int sockfd, connfd;
    char *t = "INIT1";
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
    servaddr.sin_port = htons(KDCPORT);
    if (connect(sockfd, (SA *)&servaddr, sizeof(servaddr)) != 0)
    {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the KDC..\nInitial Key Exchange Started");
    send_to(sockfd, t);
    read(sockfd, buff, sizeof(buff));
    buff[8] = '\0';
    close(sockfd);
    return buff;
}

int parse_kdc_response(char *buff, char *session_key)
{
    for (int i = 0; i < 8; i++)
        session_key[i] = buff[i];
    return buff[8];
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
// Driver function
int main()
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;
    miracl *mip = mirsys(5000, 10);
    char session_key[16];
    char key[16];
    long nounce;
    char *sNounce[6];
    char msg[100];
    char buff[MAX];

    initial_key_exchange(key);
    printf("\nGot initial key from server %s size %d\n", key, strlen(key));
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(BOBPORT);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA *)&servaddr, sizeof(servaddr))) != 0)
    {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0)
    {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Bob is waiting for alice..\n");
    len = sizeof(cli);

    // Accept the data packet from client and verification
    while (1)
    {
        connfd = accept(sockfd, (SA *)&cli, &len);
        if (connfd < 0)
        {
            printf("server acccept failed...\n");
            exit(0);
        }
        bzero(buff, MAX);
        bzero(msg, MAX);
        read(connfd, buff, sizeof(buff));
        printf("\n\n\nGot ticket\nDecrypting....");
        decrypt(buff, key, 9);
        printf("\nDecrypted Ticket with bob's key %s size %d", buff, strlen(buff));
        char sender_id = parse_kdc_response(buff, session_key);
        if (sender_id == '0') //checking for alice sender id
            printf("\nIts Alice's msg");
        else
            printf("\nUnkknown Sender %c", sender_id);
        printf("\nSession key from msg : %s", session_key);
        nounce = genNounce();
        getNounceString(nounce, sNounce);
        printf("\nNounce generated at BOB : %s", sNounce);
        strcpy(msg, sNounce);
        printf("\nEncrypting nounce %s with Session key and sending to Alice", msg);
        encrypt(msg, session_key);
        write(connfd, msg, 6);
        bzero(msg, 100);
        read(connfd, msg, 6);
        decrypt(msg, session_key, 6);
        printf("\nGot back Nounce from Alice(Decrypted with Session key) %s", msg);
        close(connfd);
    }

    close(sockfd);
}