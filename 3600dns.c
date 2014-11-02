/*
 * CS3600, Spring 2014
 * Project 3 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "3600dns.h"

/**
 * This function will print a hex dump of the provided packet to the screen
 * to help facilitate debugging.  In your milestone and final submission, you 
 * MUST call dump_packet() with your packet right before calling sendto().  
 * You're welcome to use it at other times to help debug, but please comment those
 * out in your submissions.
 *
 * DO NOT MODIFY THIS FUNCTION
 *
 * data - The pointer to your packet buffer
 * size - The length of your packet
 */
static void dump_packet(unsigned char *data, int size) {
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
            
        c = *p;
        if (isprint(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

// Get the request options.
// ./3600dns @<server:port> <name>
request_options get_request_options(char *arg[]) {
	request_options opts;

	// get the server and port
	char *a1 = arg[1];
	// length of <@server:port>
	int a1_size = strlen(a1);
  // get rid of leading @
	a1++;
	// length of <server>
	int server_len = a1_size;
	// length of <port>
	int port_len = 0;
	// look for the : delimiter
	for (int i = 0; i < a1_size; i++) {
		// port option specified
		if (a1[i] == ':') {
			server_len = i;
    	port_len = a1_size - i;
			break;
		}
	}

	// get the server; null term the last char
	strncpy(opts.server, a1, server_len);
	opts.server[server_len - 1] = '\0';

	//get the port if specified
	if (port_len) {
		char *port[port_len+1]; //+1 for '/0'
	  strncpy(port, a1+server_len+1, port_len);
	  opts.port = (short) atoi(port);
	}
	// no port specified, default is 53
	else {
	  opts.port = PORT;
	}

	// get the name
	opts.name = arg[2];

	return opts;
}

// Sets the query in the request packet. Updates req_size appropriately.
void set_query(char **req, int *req_size) {
  // size should be initialized
	if (req_size == NULL) {
		return;
	}

	// update the packet size with query size
	int query_size = sizeof(short) * BYTE_TO_BITS;
	*req_size += query_size;
	*req = (unsigned char *) realloc(*req, query_size);

	// the query id
	short id = (short) ID;

	// update the packet
	(*req)[0] = (id >> BYTE_TO_BITS) & 0xFF;
	(*req)[1] = id & 0xFF;
}

// Sets the flags in the request packet. 
// Updates req_size appropriately.
// QR, OPCODE,  AA, TC, RD, RA, Z, RCODE are set here.
void set_flags(char **req, int *req_size) {
  // size should be initialized
	if (req_size == NULL) {
		return;
	}
  // TODO
}

// Creates a dns request packet. Returns a malloced packet.
char *create_dns_request(char *name) {
	// number of bits in the packet
	int req_size = 0;
	// the request packet
	unsigned char *req = NULL; 

	// set query field
	set_query(&req, &req_size);

	// set the flags
	//set_flags(&req, &req_size);

	return req;
}

int main(int argc, char *argv[]) {
  // ./3600dns @<server:port> <name>
  if (argc != 3) {
  	printf("Usage: ./3600dns @<server:port> <name>");
  	return -1;
	}
  // process the arguments
  request_options opts = get_request_options(argv);

  // construct the DNS request
   unsigned char *packet = create_dns_request(opts.name);

   dump_packet(packet, strlen(packet));
  
  // first, open a UDP socket  
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // next, construct the destination address
  struct sockaddr_in out;
  out.sin_family = AF_INET;
  out.sin_port = htons(opts.port);
  out.sin_addr.s_addr = inet_addr(opts.server);

  // My address
  printf("My unreadable address is %u\n", out.sin_addr.s_addr); // TODO remove



  // send the DNS request (and call dump_packet with your request)
/*
  if (sendto(sock, <<your packet>>, <<packet len>>, 0, &out, sizeof(out)) < 0) {
    // an error occurred
  }

  // wait for the DNS reply (timeout: 5 seconds)
  struct sockaddr_in in;
  socklen_t in_len;

  // construct the socket set
  fd_set socks;
  FD_ZERO(&socks);
  FD_SET(sock, &socks);

  // construct the timeout
  struct timeval t;
  t.tv_sec = <<your timeout in seconds>>;
  t.tv_usec = 0;

  // wait to receive, or for a timeout
  if (select(sock + 1, &socks, NULL, NULL, &t)) {
    if (recvfrom(sock, <<your input buffer>>, <<input len>>, 0, &in, &in_len) < 0) {
      // an error occured
    }
  } else {
    // a timeout occurred
  }

  // print out the result
*/
  return 0;
}
