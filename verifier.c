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

int main( int argc, char *argv[] ) {
   int sockfd, newsockfd, portno, clilen;
   char buffer[MAX];
   char buffer1[MIN];
   struct sockaddr_in serv_addr, cli_addr;
   int  n,choice;

   /* First call to socket() function */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }
   
   /* Initialize socket structure */
   bzero((char *) &serv_addr, sizeof(serv_addr));
   
   portno = 5001;
   
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);

     /* Now bind the host address using bind() call.*/
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR on binding main server");
      exit(1);
   }
      
   /* Now start listening for the clients, here process will
      * go in sleep mode and will wait for the incoming connection
   */
   
   listen(sockfd,5);
   clilen = sizeof(cli_addr);
   
   /* Accept actual connection from the client */
   newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, (socklen_t *)&clilen);
	
   if (newsockfd < 0) {
      perror("ERROR on accept");
      exit(1);
   }
   
   /* If connection is established then start communicating */
   bzero(buffer,MAX);
			recv(newsockfd,buffer, MAX, 0);
			string enkey;
			string recovered;
			enkey = buffer;//encoded key

			//from case-2
			//send a nonce and wait for response
			//gen a nonce in byte format
			SecByteBlock nonce(16);
			AutoSeededRandomPool prng;
			prng.GenerateBlock(nonce, nonce.size());
			//convert to string
			string str(reinterpret_cast<const char*>(&nonce[0]), nonce.size());
			
			//convert to char arr and send
			char temp[str.size() + 1];
			str.copy(temp, str.size() + 1);
			temp[str.size()] = '\0';
			strcpy(buffer, temp);
			send(newsockfd, buffer, MAX, 0);
			
			//wait for response
			bzero(buffer,MAX);
			recv(newsockfd, buffer, MAX, 0); //cipher in hex format
			string encipher = buffer;//encoded cipher

			//hex decoder for key & ciphered nonce
			string key, cipher;

			StringSource ssk(enkey, true /*pumpAll*/,
			    new HexDecoder(
				new StringSink(key)
			    ) // HexDecoder
			); // StringSource

			StringSource ssv(encipher, true /*pumpAll*/,
			    new HexDecoder(
				new StringSink(cipher)
			    ) // HexDecoder
			); // StringSource	

			//decode the encrypted nonce
			try
			{
				ECB_Mode< AES >::Decryption d;
				d.SetKey((const byte*)key.data(), key.size());

				// The StreamTransformationFilter removes
				//  padding as required.
				StringSource s(cipher, true, 
					new StreamTransformationFilter(d,
						new StringSink(recovered)
					) // StreamTransformationFilter
				); // StringSource

				cout << "recovered text: " << recovered << endl;
			}
			catch(const CryptoPP::Exception& e)
			{
				cerr << e.what() << endl;
				exit(1);
			}			
			char op[20];
			if((recovered.compare(str)) == 0) 
        			 strcpy(op,"Authenticated");
			else
				strcpy(op,"Not Authenticated");	
			
			cout<<op<<endl;
			//send the result to claimant
			bzero(buffer, MAX);
			strcpy(buffer,op);
			send(newsockfd, buffer, MAX, 0);
		
   printf("Client closed the connection");
   close(newsockfd);
   close(sockfd);
   return 0;
}
