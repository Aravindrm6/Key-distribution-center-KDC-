# Key-distribution-center-KDC-
The project implements the Needham Schroder protocol. It has three modules. The client alice.c, the server bob.c and the key distribution center kdc.c
Steps:
1. Run the client alice.c first to send nonce and initial message to KDC. The KDC encrypts session key with alice-KDC shared key and sends it to alice.
2. Alice decrypts the message received from KDC to obtain session key. She sends the remaining part of the message which is encrypted with bob-KDC shared key to bob.
3. Run server bob.c to receive message from alice to receive shared session key.
