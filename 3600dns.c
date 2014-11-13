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
// ./3600dns [-ns|-mx] @<server:port> <name>
request_options get_request_options(int argc, char *arg[]) {
	// the request options to return
	request_options opts;
	// are the options valid?
	opts.valid = 0;

  // ./3600dns [-ns|-mx] @<server:port> <name>
  if (!(argc == 3 || argc == 4)) {
  	printf("ERROR\tUsage: ./3600dns @<server:port> <name>\n");
  	return opts;
	}

	// check for -ns|-mx flags
	if (argc == 4) {
		char *flag = arg[1];
		// ns record query
		if (strcmp(flag, "-ns") == 0) {
			opts.qtype = 0x0002;
		}
		// mx record query
		else if (strcmp(flag, "-mx") == 0) {
			opts.qtype = 0x000f;
		}
		// invalid flag / input is not in the correct order
		else {
  	  printf("ERROR\tUsage: ./3600dns [-ns|-mx] @<server:port> <name>\n\
  	  		[-ns|-mx] are the only supported flags\n");
			return opts;
		}
		// done checking flags
		arg++;
	}
	// default qtype
	else {
		opts.qtype = 0x0001;
	}

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

	// invalid ip address for server
	if (server_len > IP_LEN) {
  	printf("ERROR\tUsage: ./3600dns [-ns|-mx] @<server:port> <name>\n\
  			<server> should be a valid IP address\n");
		return opts;
	}

	// get the server; null term the last char
	strncpy(opts.server, a1, server_len);
	opts.server[server_len] = '\0';
	//get the port if specified
	if (port_len) {
		char port[port_len+1]; //+1 for '/0'
	  strncpy(port, a1+server_len+1, port_len);
	  opts.port = (unsigned short) atoi(port);
	}
	// no port specified, default is 53
	else {
	  opts.port = PORT;
	}
	// get the name
	opts.name = arg[2];
	// return the valid options
	opts.valid = 1;
	return opts;
}

// Sets the given param in the given request packet. 
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param param is the param to set.
// Updates the size of the request packet accordingly.
// return 0, on success 
// return = -1, invalid args to the function
int set_param(unsigned char **req, size_t *req_size, unsigned short param) {
  // NULL checks
	if (req == NULL || req_size == NULL) {
		return -1;
	}
	// update the packet size with the param size
	size_t param_size = sizeof(param);
	*req_size += param_size;
	*req = (unsigned char *) realloc(*req, *req_size);
	// update the packet
	(*req)[*req_size - param_size--] = (param >> BYTE_TO_BITS) & 0xFF;
	(*req)[*req_size - param_size] = param & 0xFF;
	return 0;
}

// Sets the given octet in at given place in the given request packet. 
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param octet is the octet to set.
// Updates the size of the request packet accordingly.
// return 0, on success 
// return = -1, invalid args to the function
int set_octet(unsigned char **req, size_t *req_size, unsigned char octet) {
  // NULL checks
	if (req == NULL || req_size == NULL) {
		return -1;
	}
	// update the packet size with the octet size
	size_t octet_size = sizeof(octet);
	*req_size += octet_size;
	*req = (unsigned char *) realloc(*req, *req_size);
	// update the packet
	(*req)[*req_size - octet_size] = octet & 0xFF;
	return 0;
}

// Sets the QNAME of the question in the given request packet.
// Updates the size of the request packet accordingly.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param name is the QNAME of the packet.
// The param *req will contain the packet of size *req_size.
// return 0, on success 
// return = -1, invalid args to the function
int set_qname(unsigned char **req, size_t *req_size, char *name) {
  // NULL checks
	if (req == NULL || *req == NULL || req_size == NULL || *req_size == 0 || name == NULL) {
		return -1;
	}
	//get each . delimited token and add each token's length
	// followed by the token to the packet.
	size_t name_len = strlen(name) + 1;
	size_t token_start_idx = 0;
	size_t token_end_idx = 0;
	size_t token_len = 0;
  for (size_t i = 0; i < name_len; i++) {
  	// we hit the end of a token
  	// add its length to the packet
  	if (name[i] == '.' || name[i] == '\0') {
      set_octet(req, req_size, (unsigned char) token_len);
      token_end_idx = token_start_idx + token_len;
      // add each octet (char/byte) from the token
      for (size_t j = token_start_idx; j < token_end_idx; j++) {
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
	return 0;
}

// Sets the question in the given request packet.
// The param name is the QNAME of the packet.
// The param qtype is the QTYPE of the packet.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param *req will contain the packet of size *req_size.
// Updates the size of the request packet accordingly.
// return 0, on success 
// return = -1, invalid args to the function
int set_question(char *name, unsigned short qtype, unsigned char **req, size_t *req_size) {
  // NULL checks
	if (req == NULL || *req == NULL || req_size == NULL || *req_size == 0 || name == NULL) {
		return -1;
	}
	// set QNAME
	set_qname(req, req_size, name);
	// set QTYPE
	set_param(req, req_size, qtype);
	// set QCLASS
	set_param(req, req_size, (unsigned short) QCLASS_CODE);
	return 0;
}

// Sets the header in the given request packet.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// Updates the size of the request packet accordingly.
// return 0, on success 
// return = -1, invalid args to the function
int set_header(unsigned char **req, size_t *req_size) {
	// only null pointers allowed so *req ends up being a newly malloced string. 
	if (req == NULL || *req != NULL || req_size == NULL || *req_size != 0) {
		return -1;
	}

	// set ID
	set_param(req, req_size, (unsigned short) ID);
	// set flags
	set_param(req, req_size, (unsigned short) FLAG_CODE);
	// set QDCOUNT
	set_param(req, req_size, (unsigned short) QD_CODE);
	// set ANCOUNT
	set_param(req, req_size, (unsigned short) AN_CODE);
	// set NSCOUNT
	set_param(req, req_size, (unsigned short) NS_CODE);
	// set ARCOUNT
	set_param(req, req_size, (unsigned short) AR_CODE);
	return 0;
}

// Creates a dns request packet. 
// The param name is the QNAME of the packet.
// The param qtype is the QTYPE of the packet.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param *req will contain the packet of size *req_size.
// return 0, on success 
// return = -1, invalid args to the function
int create_dns_request(char *name, unsigned short qtype, unsigned char **req, size_t *req_size) {
	// only null pointers allowed so *req ends up being a newly malloced string. 
	if (req == NULL || *req != NULL || req_size == NULL || *req_size != 0) {
		return -1;
	}

	// set the DNS header
	set_header(req, req_size);
	// set the DNS question
	set_question(name, qtype, req, req_size);
	return 0;
}

// Gets the next param in the given response packet at the given index. 
// A param is two bytes/octets.
// return param, on success 
// return = -1, invalid args to the function
unsigned short get_param(unsigned char *res, size_t *res_i) {
  // NULL checks
	if (res == NULL || *res == NULL) {
		return -1; // FIXME well, this may not work
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
// Updates the param aa to reflect the AA flag.
// return 0, on success
// return -1, TC
// return -2, !RA
// return -3, rcode error
int check_flags(unsigned short flags, unsigned int *aa) {
	// authoritative response
	*aa = (flags >> 10) & 0x01;
	// truncated
	unsigned char tc = (flags >> 9) & 0x01;
	// recursion available
	unsigned char ra = (flags >> 7) & 0x01;
	// response code
  unsigned char rcode = flags & 0x0f;
	// need to check TD
	if (tc) {
		printf("ERROR\tTruncated response\n");
		return -1; 
	}
	// need to check !RA
	if (ra == 0) {
		printf("ERROR\tRecursion not available\n");
		return -2;
	}
	// check the RCODE
  if (rcode != 0) {
  	print_error_code(rcode);
    return -3;
  }
  return 0;
}

// Gets the header in the given response packet.
// The param res should be a pointer to a start of a response packet.
// Returns the ANCOUNT of the packet on success; else returns an error
// code.
// return >= 0, ANCOUNT
// return = -1, invalid args to the function
// return = -2, invalid query id in the received packet
// return = -3, invalid flags (TC or !RA) or rcode error
int check_header(unsigned char *res, size_t res_len, size_t *res_i, unsigned int *aa) {
	// check input; make sure the incoming packet had enough
	// bits to contain a header (6 sections of 2 bytes each)
	if (res == NULL || *res_i != 0) {
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
	if (check_flags(flags, aa) < 0) {
		return -3;
	}

	// skip QDCOUNT
  get_param(res, res_i);
	// get ANCOUNT
	unsigned short ancount = get_param(res, res_i);
	// get NSCOUNT
	unsigned short nscount = get_param(res, res_i);
	// skip ARCOUNT
  get_param(res, res_i);

	return ancount;
}

// Checks the given rcode param for errors and prints the
// right error out.
// Possible RCODE values:
//   0  -> No error condition
//   1  -> Format error (name serve unable to interpret query)
//   2  -> Server failure (name server unable to process, name server error)
//   3  -> Name error (domain name reference in query does not exist)
//   4  -> Not Implemented (name server does not support requested query type)
//   5  -> Refused (name server refuses op, policy reasons)
void print_error_code(unsigned char rcode) {
  // Handle possible errors
  if (rcode == 1) {
    printf("ERROR\tRCODE - Format Error\n");
  }
  else if (rcode == 2) {
    printf("ERROR\tRCODE - Server Failure\n");
  }
  else if (rcode == 3) {
    printf("NOTFOUND\n");
  }
  else if (rcode == 4) {
    printf("ERROR\tRCODE - Not Implemented\n");
  }
  else if (rcode == 5) {
    printf("ERROR\tRCODE - Refused\n");
  }
  else if (rcode > 5) {
    printf("ERROR\tRCODE - Unknown\n");
  }
}

// Is the value at the given index in the response a pointer
// Return the address of the pointer or 0, if not pointer
int is_pointer(unsigned char *res, size_t *res_i) { 
  // Get the location where the pointer would be
  size_t val = res[*res_i];
  size_t idx = *res_i;
  // This should reprsent the top two bits where pointer would be
  int pointer = val >> 6;

  // if the last two bits are both 1's it is a pointer
  if (pointer == 3) {
    // Capture the first part of the offset
    short offset = res[idx++];
    // Remove the top two bits
    offset &= 0x3f;
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

// Given the index to a name (res_i) walk over it to
// The next segement of the packet (reflected in res_i)
void walk_name(unsigned char *res, size_t *res_i) {
  // We want to walk past the name to the good stuff
  // See if this is a pointer
  if (is_pointer(res, res_i)) {
    // skip over the pointer
    (*res_i) += 2;
  }
  // Else walk to the end of the name
  else {
    // Names are terminated with a 0 or a pointer
    // If we don't we might get false positives
    while (res[(*res_i)] != 0) {
      // Check if it is a pointer, pointer signifies the end of a name
      if (is_pointer(res, res_i)) {
        // Move it along one, will be set to next outside of loop
        (*res_i)++;
        break;
      }
      // Not a pointer, must be a number, jump that number of places + 1
      // ex 3www -> jump to the index after the last w
      (*res_i) += res[*res_i] + 1;
    }
    // Move it to the starting index of the object after name
    (*res_i)++;
  }
}

// Given a response and an index into the response
// Get the answer and print it out
// aa is flag that says if res was auth
void get_answer(unsigned char *res, size_t *res_i, unsigned int aa) {

  // Capture the correct string for auth/nonauth
  char *auth = "nonauth";
  // Should be auth
  if (aa) {
    // It should be auth
    auth = "auth";
  }
  // Walk over the name to the type segement
  walk_name(res, res_i); 
  // Get the type of answer
  short type = get_param(res, res_i);
  
  // Get past Class (2 bytes), TIL (4 bytes) and RDLENGTH (2 bytes)
  (*res_i) += 6;
  unsigned short rd_len = get_param(res, res_i);

  // 'A' Record, spit out IP (exactly 4 octets)
  if (type == 1) {
    // We should be at the beginning of RDATA
    // We should only be reading the 4 octets
    get_ip(res, res_i, aa);
  }
  // 'CNAME' Record, spit out the CNAME (abitrary length)
  else if (type == 5) {
    // We should be reading the whole size of rd_length
    char *name = get_name(res, res_i, aa, rd_len);
    printf("CNAME\t%s\t%s\n", name, auth);
  }
  // 'NS' Record, spit out the NS 
  else if (type == 2) {
    char *name = get_name(res, res_i, aa, rd_len);
    printf("NS\t%s\t%s\n", name, auth);
  }
  // 'MS' Record. spit out the MS
  else if (type == 15) {
    int preference = get_param(res, res_i);
    // subtract 2 b/c of preference
    char * name = get_name(res, res_i, aa, rd_len - 2);
    printf("MX\t%s\t%d\t%s\n", name, preference, auth);
  }
}

// Get the ip address located at the offset of the response
// print the correct auth based off of aa flag
void get_ip(unsigned char *res, size_t *res_i, unsigned int aa) {
  //  This will store the four integers comprising the IP 
  int ip[4];
  // Capture the four numbers for the ip
  for (int i = 0; i < 4; i++) {
    ip[i] = res[(*res_i)++];
  }
  // Read the 4 octets 
  if (aa) {
    printf("IP\t%d.%d.%d.%d\tauth\n", ip[0], ip[1], ip[2], ip[3]);
	}
	else {
    printf("IP\t%d.%d.%d.%d\tnonauth\n", ip[0], ip[1], ip[2], ip[3]);
	}
}

// Given a response and starting location
// Read the response and append it to the given string 'name'
void add_word(unsigned char *res, size_t *res_i, char **name, size_t *name_len) {
  // Get the length of the word we are going to add
  size_t len = res[(*res_i)++];
  // Make name big enough to hold the new word
  *name = realloc(*name, ((*name_len) + len));
  // Copy new word into name
  for (size_t i = 0; i < len; i++) {
    // Copy one character at a time
    (*name)[(*name_len) + i] = res[(*res_i)++];
  }
  // Update the name_len to reflect the added word
  (*name_len) += len;
}

// This method will go through the RDATA and capture the name
// that is stored at the location beginning at res[*res_i}
// This will have to handle being redirected by pointers
char* get_name(unsigned char *res, size_t *res_i, unsigned int aa, unsigned short rd_len) {
  // Set up the name we will print
  char *name = NULL;
  // starts a 0, increment as we add words
  size_t name_len = 0;
  // index we will read next from to get a word in res
  size_t read_idx  = *res_i;
  (*res_i) += rd_len;

  // Loop through until we have read all of it
  // Should just terminate when we read a 0 as length
  while (res[read_idx] != 0) {
    // Check if it is a pointer, if it is returns location
    int pointer_len = is_pointer(res, &read_idx);

    if (pointer_len) {
      // Reset read_idx to the next location to read from pointer
      read_idx = pointer_len;
      // Capture the word there, and be set up for the word after it
      // this is reflected in updating read_idx within add_word()
      add_word(res, &read_idx, &name, &name_len);
    }
    // Not at a pointer
    else {
      // Add the word to name
      add_word(res, &read_idx, &name, &name_len);
    }

    // Add the '.' character as long as we are not at the end
    name = realloc(name, name_len + 1);
    name[name_len] = '.';
    name_len++;
  }
  // Null terminate the name,
  //  which also get's rid of the extra '.' at the end
  name[name_len-1] = '\0';
  return name;
}

// Skips past the question in the response packet.
// Updates res_i past the question and to the start of the answer.
// If the res_i pointer is not at the end of the header/start of the 
// question, return -1.
// If the request packet and the response packet's names don't match,
// return -2.
// return 0 on success.
int check_question(unsigned char *res, size_t res_len, size_t *res_i) {
  // we want to be header size into the request packet
	if (*res_i != (6 * 2)) {
		return -1;
	}
  walk_name(res, res_i);
  // skip qtype
  get_param(res, res_i);
  // skip qclass
  get_param(res, res_i);
  return 0;
}

// Deconstructs and intreprets a dns response packet.
// Prints the answers in the dns response to stdout if everything checks out.
//
// The param res should be a pointer to a response packet.
// The param res_len must be an int pointer to the length of the response packet.
//
// returns -1, invalid input; null pointers
// returns -2, invalid header
int print_dns_response(unsigned char *res, size_t res_len) {
	// valid input checks
	if (res == NULL) {
		return -1;
	}

	// the index into the response array that we are currently looking at
	size_t res_i = 0;
	// the number of answers we want
  int num_answers;
  // AA flag
  int aa = -1;
	// check the DNS header; its invalid if return is < 0; or if aa is not set, error
	if (((num_answers = check_header(res, res_len, &res_i, &aa)) < 0) || aa == -1) {
		return -2;
	}

	// we want to check the question to see if it matches the request packet's question
	// res_i should be a pointer the start of the question
	check_question(res, res_len, &res_i);

  // Capture all of the answers
  for (int i = 0; i < num_answers; i++) {
    get_answer(res, &res_i, (unsigned) aa);
  }
}

int main(int argc, char *argv[]) {
  // process the arguments
  request_options opts = get_request_options(argc, argv);

	// invalid args
	if (!opts.valid) {
		return -1;
	}

  // construct the DNS request
  size_t request_len = 0;
  unsigned char *request = NULL;
  create_dns_request(opts.name, opts.qtype, &request, &request_len);

	// Display request packet contents
  dump_packet(request, request_len);
  
  // first, open a UDP socket  
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // next, construct the destination address
  struct sockaddr_in out;
  out.sin_family = AF_INET;
  out.sin_port = htons(opts.port);
  // get the server name
  out.sin_addr.s_addr = inet_addr(opts.server);

  // send the DNS request (and call dump_packet with your request)
  if (sendto(sock, request, request_len, 0, &out, sizeof(out)) < 0) {
  	printf("ERROR\tFailed to send packet\n");
    // an error occurred
    return -1;
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
  size_t response_size;
  unsigned char response[MAX_RESPONSE_SIZE];
  if (select(sock + 1, &socks, NULL, NULL, &t)) {
    if ((response_size = recvfrom(sock, response, MAX_RESPONSE_SIZE, 0, &in, &in_len)) < 0) {
  	  printf("ERROR\tFailed to receive packet\n");
      // an error occurred
      return response_size;
    }
  } else {
    // a timeout occurred
    printf("NORESPONSE\n");
    return -2;
  }

	// print the answer from the response if it is a valid response to the request
  if (print_dns_response(response, response_size)) {
  	return -3;
	}

  return 0;
}
