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
	if (req == NULL || *req == NULL || req_size == NULL || *req_size == 0 || name == NULL) {
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
	if (req == NULL || *req == NULL || req_size == NULL || *req_size == 0 || name == NULL) {
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

// Creates a dns request packet. 
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param name is the QNAME of the packet.
// The param *req will contain the packet of size *req_size.
void create_dns_request(char *name, unsigned char **req, int *req_size) {
	// only null pointers allowed so *req ends up being a newly malloced string. 
	if (req == NULL || *req != NULL || req_size == NULL || *req_size != 0) {
		return; // TODO return error codes
	}

	// set the DNS header
	set_header(req, req_size);
	// set the DNS question
	set_question(req, req_size, name);
}

// Gets the next param in the given response packet. 
// A param is two bytes/octets.
unsigned short get_param(unsigned char *res, int *res_i) {
	// TODO update comments about res_i
	// we need to also check the size of param for out of bounds
  // NULL checks
	if (res == NULL || *res == NULL) {
		return; // TODO return error codes
	}
	// initialize the param to 0
	unsigned short param = 0;
	// update the param and packet pointer
	char *packet = *res;
	param = res[(*res_i)++];
	param <<= BYTE_TO_BITS;
	param |= res[(*res_i)++];
	return param;
}

// Check the given flag param for invalid response codes or RCODE errors.
// return 0, on success
// return -1, TR or !RA
// return -2, rcode error
int check_flags(unsigned short flags) {

	// Need to check TD TODO
	// Need to check !RA TODO

	//  Check the RCODE
  if (check_response_code(flags) != 0) {
    exit(0);
  }
}

// Gets the header in the given response packet.
// The param res should be a pointer to a start of a response packet.
// Returns the ANCOUNT of the packet on success; else returns an error
// code.
// return >= 0, ANCOUNT
// return = -1, invalid args to the function
// return = -2, invalid query id in the received packet
// return = -3, invalid flags (TR or !RA) or rcode error
int check_header(unsigned char *res, size_t res_len, int *res_i) {
	// check input; make sure the incoming packet had enough
	// bits to contain a header (6 sections of 2 bytes each)
	if (res == NULL || res_i < (6 * 2)) {
		return -1; // invalid args
	}
	// get ID
	unsigned short id = get_param(res, res_i);
	// check that we received the right packet
	if (id != ID) {
		return -2; // invalid query ID
	}
	// get flags
	unsigned short flags = get_param(res, res_i);
	// check the flags
	if (check_flags(flags) < 0) {
		return -3;
	}

	// get QDCOUNT TODO do we care to check this?
	unsigned short qdcount = get_param(res, res_i);
	// get ANCOUNT
	unsigned short ancount = get_param(res, res_i);
	// get NSCOUNT TODO do we care to check this?
	unsigned short nscount = get_param(res, res_i);
	// get ARCOUNT TODO do we care to check this?
	unsigned short arcount = get_param(res, res_i);

	return ancount;
}

// Checks RCODE from the flags param.
// Possible RCODE values:
//   0  -> No error condition
//   1  -> Format error (name serve unable to interpret query)
//   2  -> Server failure (name server unable to process, name server error)
//   3  -> Name error (domain name reference in query does not exist)
//   4  -> Not Implemented (name server does not support requested query type)
//   5  -> Refused (name server refuses op, policy reasons)
unsigned short check_response_code(unsigned short flags) {
  // Capture the RCDOE (last 4 bits of flags)
  unsigned short rcode = flags & 0x0f;
  // Handle possible errors
  if (rcode == 1) {
    printf("ERROR \t RCODE - Format Error\n");
  }
  else if (rcode == 2) {
    printf("ERROR \t RCODE - Server Failure\n");
  }
  else if (rcode == 3) {
    printf("NOTFOUND\n");
  }
  else if (rcode == 4) {
    printf("ERROR \t RCODE - Not Implemented\n");
  }
  else if (rcode == 5) {
    printf("ERROR \t RCODE - Refused\n");
  }
  else if (rcode > 5) {
    printf("ERROR\t RCODE - Unknown\n");
  }
  return rcode;
}

// Is the value at the given index in the response a pointer
// Return the address of the pointer or 0, if not pointer
int is_pointer(unsigned char *res, int *res_i) {
  // Get the location where the pointer would be
  int val = res[*res_i];
  int idx = *res_i;
  int pointer = val >> 6;

  // if the last two bits are both 1's it is a pointer
  if (pointer == 3) {
    // capture the offset
    short offset = res[idx++];
    // Remove the top two bits
    offset &= 0xc0;
    // shift it to the left
    offset = offset << 8;
    // Add the other byte to it
    offset |= res[idx];
    return (int)offset;
  }
  // Was not a pointer
  else {
    return 0;
  }
}

// Given a response and an index into the response
// Get the answer and print it out
void get_answer(unsigned char *res, int *res_i) {
  // We want to walk past the name to the good stuff
  // See if this is a pointer
  if (is_pointer(res, res_i)) {
    *res_i = *res_i + 2; // change to += TODO
  }
  // Else walk to the end of the name...
  else {
    // Names are terminated with a 0 or a pointer
    // TODO THIS MIGHT BE A BUG
    // We might only want to check the locations where there
    // should be a number or poiter than skip ahead to the next
    // If we don't we might get false positives
    while (res[(*res_i)] != 0) {
      // Check if it is a pointer
      if (is_pointer(res, res_i)) {
        // Move it along one, will be set to next outside of loop
        (*res_i)++;
        break;
      }
      // Check the next one
      (*res_i)++;
    }
    // Move it to the starting index of the object after name
    (*res_i)++;
  }

  // Get the type of answer
  short type = get_param(res, res_i);
  // Get the class of the answer data
  short class = get_param(res, res_i);  
  
  // Get past TIL (4 bytes)
  short til = get_param(res, res_i);
  til = get_param(res, res_i);
  // Capture RDLENGTH
  short rd_length = get_param(res, res_i);
  // 'A' Record, spit out IP (exactly 4 octets)
  if (type == 1) {
    // We should be at the beginning of RDATA
    // We should only be reading the 4 octets
    get_ip(res, res_i);
  }
  // CNAME -> read it
  // TODO Recycle the code from the top to actually get the name
  else if (type == 5) {
    // We should be reading the whole size of rd_length
    get_name(res, res_i, rd_length);
  }
  // TODO Add logic for MX and NS

  return;
}

// Get the ip address located at the offset of the response
char* get_ip(unsigned char *res, int * res_i) {
  // TODO Complete logic
  char *ip_addr;
  
  //TODO Get this to work for auth/nonauth
  printf("IP \t %s auth", ip_addr);
}
// Given a response and starting location
// Read the response and append it to the given string 'name'
void add_word(unsigned char *res, int *res_i, char *name, int *name_len) {

  // Get the length of the word we are going to add
  int len = res[(*res_i)++];

  // Make name big enough to hold the new word
  realloc(name, (*name_len + len));
  // Copy new word into name
  for (int i = 0; i < len; i++) {
    // Copy one character at a time
    name[*name_len + i] = res[(*res_i)++];
  }
  // Update the name_len
  *name_len = *name_len + len;
}

// This method will go throught he RDATA and capture the name
// that is stored at the location beggining at res[*res_i}
// This will have to handle being redirected by pointers
char* get_name(unsigned char *res, int *res_i, int rd_len) {
  // TODO Check if pointer, send it through that logic
  // Otherwise call add_word
  char *name = "";
  int name_len = 0;
  // Retain where RDATA begins, will be useful for pointers
  int start_loc = *res_i;
  // how much we have read so far
  int read = 0;

  // Loop through until we have read all of it
  while (read <= rd_len) {
    // Check if it is a pointer, if it is returns location
    int pointer_len = is_pointer(res, res_i);
    if (pointer_len) {
      // We do not want to affect the position of res_i
      // when reading a pointer, use a temp
      int tmp = start_loc + pointer_len;
      // Location of pointer
      // TODO Do we need to be adding starting position???
      // Add the word starting at the pointer loc
      add_word(res, &tmp, name, &name_len);
      // Increment for pointer and location
      *res_i = *res_i + 2;
      read += 2;
    }
    else {
      // Increment for the amount we will be reading
      // Because it is not a poinyer the value will be stored in the 
      // first index
      read += res[*res_i];
      // Add the word to name
      add_word(res, res_i, name, &name_len);
    }
    // Add the '.' character as long as we are not at the end
    if (read <= rd_len) {
      realloc(name, name_len + 1);
      name[name_len] = '.';
      name_len++;
    }
  }

  // Null terminate the name
  realloc(name, name_len + 1);
  name[name_len] = '\0';

  // TODO Make this work for auth/nonauth
  printf("CNAME \t %s \t auth", name);
}

// Deconstructs and intreprets a dns response packet. Ensures that the response packet
// is the response to the given request packet. Prints the answers in the dns response
// to stdout if everything checks out.
//
// The param res should be a pointer to a response packet.
// The param res_len must be an int pointer to the length of the response packet.
// The param req should be a pointer to a request packet.
// The param req_len must be an int pointer to the length of the request packet.
// 
// TODO this function is disgusting, Just print the deconstructed response in this
// function. Better thing to do would be to return the deconstructed response,
// however that could entail some serious pointer madness. There could be 
// multiple responses and that means we would be returning an array (a pointer)
// to a bunch of strings (more pointers). A simplification of this is that
// we can assume that what we are return are an array of null terminated strings
// meaning we don't need to return the size of each string because we can get it
// via strlen(). However, we would need to return the length of the returned array
// which would require adding another parameter. This would make us have 5 params
// which is pretty bulky and ugly looking.
void print_dns_response(unsigned char *res, size_t res_len, unsigned char *req, int req_len) {
	// valid input checks
	if (res == NULL || req == NULL) {
		return; // TODO return error code
	}

	// the index into the response array that we are currently looking at
	int res_i = 0;
	// the number of answers we want
  int num_answers = 0;
	// check the DNS header; its invalid if return is < 0
	if (num_answers = check_header(res, res_len, &res_i) < 0) {
		return; // TODO return error code
	}

	// we want to check the question to see if it matches the request packet's question
	// res_i should be a pointer the start of the ques
	// check_question(res, res_len, res_i, req, req_len) // TODO we want to skip header size into the request packet

/*
  // Capture all of the answers...
  for (int i = 0; i < num_answers; i++) {
    get_answer(res, &res_i);
  }
*/
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
  int request_len = 0;
  unsigned char *request = NULL;
  create_dns_request(opts.name, &request, &request_len);

	// Display request packet contents
  dump_packet(request, request_len);
  
  // first, open a UDP socket  
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // next, construct the destination address
  struct sockaddr_in out;
  out.sin_family = AF_INET;
  out.sin_port = htons(opts.port);
  out.sin_addr.s_addr = inet_addr(opts.server);

  // send the DNS request (and call dump_packet with your request)
  if (sendto(sock, request, request_len, 0, &out, sizeof(out)) < 0) {
    // an error occurred
    return -1; // TODO CONFIRM THIS BEHAVIOR
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
  t.tv_sec = 5;
  t.tv_usec = 0;

  // wait to receive, or for a timeout
  int response_size;
  unsigned char response[MAX_RESPONSE_SIZE];
  if (select(sock + 1, &socks, NULL, NULL, &t)) {
    if (response_size = recvfrom(sock, response, MAX_RESPONSE_SIZE, 0, &in, &in_len) < 0) {
      // an error occurred
      return -3; // TODO confirm this behavior
    }
  } else {
    // a timeout occurred
    printf("NORESPONSE\n");
    return -2; // TODO confirm this behavior
  }

	// print the answer from the response if it is a valid response to the request
  print_dns_response(response, response_size, request, request_len);

  return 0;
}
