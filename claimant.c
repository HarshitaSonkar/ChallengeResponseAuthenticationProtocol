#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include<bits/stdc++.h>
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::ECB_Mode;
using namespace CryptoPP;
using namespace std;

#define MAX 100
#define MIN 2


int main(int argc, char *argv[]) {
   int sockfd, portno, n;
   struct sockaddr_in serv_addr;
   struct hostent *server;
   
   char buffer[MAX];
   char buffer1[MIN];
   
   if (argc < 3) {
      fprintf(stderr,"usage %s hostname port\n", argv[0]);
      exit(0);
   }
	
   portno = atoi(argv[2]);
   
   /* Create a socket point */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }
	
   server = gethostbyname(argv[1]);
   
   if (server == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      exit(0);
   }
   
   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
   serv_addr.sin_port = htons(portno);
   
   /* Now connect to the server */
   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR connecting");
      exit(1);
   }
   
   /* Now ask for a message from the user, this message
      * will be read by server
   */
			//cout<<"Signup"<<"\n";
			int id = 1;
			AutoSeededRandomPool prng;

			byte key[AES::DEFAULT_KEYLENGTH];
			prng.GenerateBlock(key, sizeof(key));

			string encoded,cipher;

	
			// Encoding Key
			encoded.clear();
			StringSource(key, sizeof(key), true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			cout << "key: " << encoded << endl;

			//send key
			char temp[encoded.size() + 1];
			encoded.copy(temp, encoded.size() + 1);
			temp[encoded.size()] = '\0';
			strcpy(buffer, temp);
			send(sockfd, buffer, MAX, 0);
			
			//recv nonce
			bzero(buffer,MAX);
			recv(sockfd, buffer, MAX, 0);
			string nonce = buffer;
			
			try
			{
				cout << "nonce is " << nonce << endl;

				ECB_Mode< AES >::Encryption e;
				e.SetKey(key, sizeof(key));

				// The StreamTransformationFilter adds padding
				//  as required. ECB and CBC Mode must be padded
				//  to the block size of the cipher.
				StringSource(nonce, true, 
					new StreamTransformationFilter(e,
						new StringSink(cipher)
					) // StreamTransformationFilter      
				); // StringSource
			}
			catch(const CryptoPP::Exception& e)
			{
				cerr << e.what() << endl;
				exit(1);
			}
			
			//encode the cipher to hex format
			encoded.clear();
			StringSource(cipher, true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			cout << "cipher text: " << encoded << endl;
			
			//to char array to send as packet
			char temp1[encoded.size() + 1];
			encoded.copy(temp1, encoded.size() + 1);
			temp1[encoded.size()] = '\0';
			strcpy(buffer, temp1);
			send(sockfd, buffer, MAX, 0);
			
			bzero(buffer, MAX);
			recv(sockfd, buffer, MAX, 0);
			cout<<buffer<<endl;// Authenticated or not

   //close(sockfd);*/
   return 0;
}
