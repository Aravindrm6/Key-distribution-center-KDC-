#include "miracl.h"
#include <time.h>
#include <netdb.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#define MAX 80
#define PORT 8081
#define SA struct sockaddr
#define ALICE 0
#define BOB 1

void encrypt(char *msg, char *key) // same for encrypt and decrypt
{
    int len = strlen(key);
    int i;
    for (i = 0; msg[i]; i++)
    {
        msg[i] = msg[i] ^ key[i % len];
    }
}

void decrypt(char *msg, char *key, int size) // len of message based on protocal used
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

// Driver function
int main()
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;
    miracl *mip = mirsys(5000, 10);
    char *session_key[16];
    char keys[2][16];
    char nounce[6];
    char msg[100];
    char buff[MAX];
    genString(keys[ALICE], 8);
    genString(keys[BOB], 8);

    printf("\nGen keys:\nA : %s\nB : %s\n", keys[ALICE], keys[BOB]);
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
    servaddr.sin_port = htons(PORT);

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
        printf("Server listening..\n");
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
        if (strncmp(buff, "0", 1) == 0) /// Sender id ALICE
        {
            printf("\nALICEid+BOBid+nounce : %s", buff);
            int j = 0;
            bzero(session_key, 16);
            for (int i = 2; i < 8; i++) // getting nounce from msg
                nounce[j++] = buff[i];
            nounce[j] = '\0';
            genString(session_key, 8); /// gen session key
            printf("\nSession key : %s\nNounce : %s", session_key, nounce);
            strcat(msg, nounce);      // addinf nounce
            msg[6] = '0' + BOB;       // appennding bobs id
            strcat(msg, session_key); // adding session_key
            for (j = 0; session_key[j]; j++)
                ;
            session_key[j] = '0' + ALICE; // adding alice id on the back for the ticket to bob
            printf("\nMsg prepared is(nounce+BOBid+session_key) %s\nTicket to bob(session+aliceID) is %s", msg, session_key);
            encrypt(session_key, keys[BOB]); // encrypting alice id + session key with bob key
            printf("\nEncrypting %s with %s -- %d size\n", msg, keys[ALICE], strlen(keys[ALICE]));
            encrypt(msg, keys[ALICE]); //encrypt everuthing with alice
            write(connfd, msg, 15);
            write(connfd, session_key, 9); // sent to alice
        }
        if (strncmp(buff, "1", 1) == 0)
        {
            printf("BOB IS HERER\nans saying %s", buff);
        }
        if (strncmp(buff, "INIT", 4) == 0)
        {
            printf("Giving Initial keys\n");
            write(connfd, keys[buff[4] - '0'], 16);
        }
        close(connfd);
    }

    close(sockfd);
}