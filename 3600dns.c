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
	// the request options to return
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
		char port[port_len+1]; //+1 for '/0'
	  strncpy(port, a1+server_len+1, port_len);
	  opts.port = (short) atoi(port);
	}
	// no port specified, default is 53
	else {
	  opts.port = PORT;
	}
	// get the name
	opts.name = arg[2];
	// return the options
	return opts;
}

// Sets the given param in the given request packet. 
// Updates the size of the request packet accordingly.
void set_param(unsigned char **req, int *req_size, short param) {
  // NULL checks
	if (req == NULL || req_size == NULL) {
		return; // TODO return error codes
	}
	// update the packet size with the param size
	int param_size = sizeof(param);
	*req_size += param_size;
	*req = (unsigned char *) realloc(*req, *req_size);
	// update the packet
	(*req)[*req_size - param_size--] = (param >> BYTE_TO_BITS) & 0xFF;
	(*req)[*req_size - param_size] = param & 0xFF;
}

// Sets the given octet in at given place in the given request packet. 
// Updates the size of the request packet accordingly.
void set_octet(unsigned char **req, int *req_size, unsigned char octet) {
  // NULL checks
	if (req == NULL || req_size == NULL) {
		return; // TODO return error codes
	}
	// update the packet size with the octet size
	int octet_size = sizeof(octet);
	*req_size += octet_size;
	*req = (unsigned char *) realloc(*req, *req_size);
	// update the packet
	(*req)[*req_size - octet_size] = octet & 0xFF;
}

// Sets the QNAME of the question in the given request packet.
// Updates the size of the request packet accordingly.
void set_qname(unsigned char **req, int *req_size, char *name) {
  // NULL checks
	if (req == NULL || req_size == NULL || name == NULL) {
		return; // TODO return error codes
	}
	//get each . delimited token and add each token's length
	// followed by the token to the packet.
	int name_len = strlen(name) + 1;
	int token_start_idx = 0;
	int token_end_idx = 0;
	int token_len = 0;
  for (int i = 0; i < name_len; i++) {
  	// we hit the end of a token
  	// add its length to the packet
  	if (name[i] == '.' || name[i] == '\0') {
      set_octet(req, req_size, (unsigned char) token_len);
      token_end_idx = token_start_idx + token_len;
      // add each octet (char/byte) from the token
      for (int j = token_start_idx; j < token_end_idx; j++) {
      	set_octet(req, req_size, (unsigned char) name[j]);
			}
			// update the start index of to the next token
			token_start_idx = token_end_idx + 1;
			// on to the next token
  		token_len = 0;
  		continue;
		}
		token_len++;
	}
	// mark the end of the question
	set_octet(req, req_size, (unsigned char) 0);
}

// Sets the question in the given request packet.
// Updates the size of the request packet accordingly.
void set_question(unsigned char **req, int *req_size, char *name) {
  // NULL checks
	if (req == NULL || req_size == NULL || name == NULL) {
		return; // TODO return error codes
	}
	// set QNAME
	set_qname(req, req_size, name);
	// set QTYPE
	set_param(req, req_size, (short) QTYPE_CODE);
	// set QCLASS
	set_param(req, req_size, (short) QCLASS_CODE);
}

// Sets the header in the given request packet.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// Updates the size of the request packet accordingly.
void set_header(unsigned char **req, int *req_size) {
	// only null pointers allowed so *req ends up being a newly malloced string. 
	if (req == NULL || *req != NULL || req_size == NULL || *req_size != 0) {
		return; // TODO return error codes
	}

	// set ID
	set_param(req, req_size, (short) ID);
	// set flags
	set_param(req, req_size, (short) FLAG_CODE);
	// set QDCOUNT
	set_param(req, req_size, (short) QD_CODE);
	// set ANCOUNT
	set_param(req, req_size, (short) AN_CODE);
	// set NSCOUNT
	set_param(req, req_size, (short) NS_CODE);
	// set ARCOUNT
	set_param(req, req_size, (short) AR_CODE);
}

// Creates a dns request packet. The param req should be a pointer to
// a NULL pointer. The param req_size must be an int pointer to 0.
// The param *req will contain the packet of size *req_size.
void create_dns_request(char *name, unsigned char **req, int *req_size) {
	// only null pointers allowed so *req ends up being a newly malloced string. 
	if (*req != NULL || req_size == NULL || *req_size != 0) {
		return; // TODO return error codes
	}

	// set the DNS header
	set_header(req, req_size);
	// set the DNS question
	set_question(req, req_size, name);
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
  int packet_len = 0;
  unsigned char *packet = NULL;
  create_dns_request(opts.name, &packet, &packet_len);

	// Display packet contents
  dump_packet(packet, packet_len);
  
	// TODO 
	/*
  // first, open a UDP socket  
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // next, construct the destination address
  struct sockaddr_in out;
  out.sin_family = AF_INET;
  out.sin_port = htons(opts.port);
  out.sin_addr.s_addr = inet_addr(opts.server);

  // send the DNS request (and call dump_packet with your request)
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
