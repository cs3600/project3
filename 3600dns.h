/*
 * CS3600, Spring 2014
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__
// Default query id to use
#define ID 1337
// Default udp port for DNS
#define PORT 53
// The number of bits in a byte
#define BYTE_TO_BITS 8

// QR code is 0 (query, not a response)
// OPCODE is 0000 (standard query)
// AA is 0 (ignored)
// TC is 0 (not truncated)
// RD is 1 (recursion requested)
// RA is 0 (not meaningful for query)
// Z is 000 (reserved)
// RCODE is 0000 (not meaningful for query)
// Binary: 0000 0001 0000 0000
// Hex: 0100
// Decimal: 256
// The default flag code in decimal
#define FLAG_CODE 256

// Binary: 0001
// Hex: 01
// Decimal: 1
// Default QDCOUNT code
// One question follows
#define QD_CODE 1

// Binary: 0000
// Hex: 00
// Decimal: 0
// Default ANCOUNT code
// No answers follow
#define AN_CODE 0 

// Binary: 0000
// Hex: 00
// Decimal: 0
// Default NSCOUNT code
// No records follow
#define NS_CODE 0

// Binary: 0000
// Hex: 00
// Decimal: 0
// Default ARCOUNT code
// No additional records follow
#define AR_CODE 0

// Binary: 0001
// Hex: 01
// Decimal: 1
// Default QCLASS code
// Represents Internet addresses
#define QCLASS_CODE 1

// Maximum response size
#define MAX_RESPONSE_SIZE 65536

// Total number of bytes in a DNS packet header
// 6 fields * 16 bits/field = 96 bits = 12 bytes
#define TOTAL_HEADER_BYTES 12

// The number of characters in an IP address
#define IP_LEN 16

// Represents the requested server ip,
// port number, and domain name in a
// logical structure.
typedef struct request_options_t {
	// are these options valid?
	unsigned int valid:1;
	// query type 
	unsigned short qtype;
	// server ip address
	// 2^32 ip addresses in IPv4
	// 255.255.255.255/0, 16 bits worst case
	char server[IP_LEN];
	// the port number
	// 2^16 ports
	unsigned short port;
	// the domain name
	char *name;
} request_options;


// Get the request options.
// ./3600dns [-ns|-mx] @<server:port> <name>
request_options get_request_options(int argc, char *arg[]); 

// Sets the given param in the given request packet. 
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param param is the param to set.
// Updates the size of the request packet accordingly.
// return 0, on success 
// return = -1, invalid args to the function
int set_param(unsigned char **req, size_t *req_size, unsigned short param); 

// Sets the given octet in at given place in the given request packet. 
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param octet is the octet to set.
// Updates the size of the request packet accordingly.
// return 0, on success 
// return = -1, invalid args to the function
int set_octet(unsigned char **req, size_t *req_size, unsigned char octet);

// Sets the QNAME of the question in the given request packet.
// Updates the size of the request packet accordingly.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param name is the QNAME of the packet.
// The param *req will contain the packet of size *req_size.
// return 0, on success 
// return = -1, invalid args to the function
int set_qname(unsigned char **req, size_t *req_size, char *name);

// Sets the question in the given request packet.
// The param name is the QNAME of the packet.
// The param qtype is the QTYPE of the packet.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param *req will contain the packet of size *req_size.
// Updates the size of the request packet accordingly.
// return 0, on success 
// return = -1, invalid args to the function
int set_question(char *name, unsigned short qtype, unsigned char **req, size_t *req_size);

// Sets the header in the given request packet.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// Updates the size of the request packet accordingly.
// return 0, on success 
// return = -1, invalid args to the function
int set_header(unsigned char **req, size_t *req_size); 

// Creates a dns request packet. 
// The param name is the QNAME of the packet.
// The param qtype is the QTYPE of the packet.
// The param req should be a pointer to a NULL pointer.
// The param req_size must be an int pointer to 0.
// The param *req will contain the packet of size *req_size.
// return 0, on success 
// return = -1, invalid args to the function
int create_dns_request(char *name, unsigned short qtype, unsigned char **req, size_t *req_size);

// Gets the next param in the given response packet at the given index. 
// A param is two bytes/octets.
// return param, on success 
// return = -1, invalid args to the function
unsigned short get_param(unsigned char *res, size_t *res_i);

// Check the given flag param for invalid response codes or RCODE errors.
// Updates the param aa to reflect the AA flag.
// return 0, on success
// return -1, TC
// return -2, !RA
// return -3, rcode error
int check_flags(unsigned short flags, unsigned int *aa);

// Gets the header in the given response packet.
// The param res should be a pointer to a start of a response packet.
// Returns the ANCOUNT of the packet on success; else returns an error
// code.
// return >= 0, ANCOUNT
// return = -1, invalid args to the function
// return = -2, invalid query id in the received packet
// return = -3, invalid flags (TC or !RA) or rcode error
int check_header(unsigned char *res, size_t res_len, size_t *res_i, unsigned int *aa);

// Checks the given rcode param for errors and prints the
// right error out.
// Possible RCODE values:
//   0  -> No error condition
//   1  -> Format error (name serve unable to interpret query)
//   2  -> Server failure (name server unable to process, name server error)
//   3  -> Name error (domain name reference in query does not exist)
//   4  -> Not Implemented (name server does not support requested query type)
//   5  -> Refused (name server refuses op, policy reasons)
void print_error_code(unsigned char rcode);

// Is the value at the given index in the response a pointer
// Return the address of the pointer or 0, if not pointer
int is_pointer(unsigned char *res, size_t *res_i);

// Given the index to a name (res_i) walk over it to
// The next segement of the packet (reflected in res_i)
void walk_name(unsigned char *res, size_t *res_i);

// Given a response and an index into the response
// Get the answer and print it out
// aa is flag that says if res was auth
void get_answer(unsigned char *res, size_t *res_i, unsigned int aa);

// Get the ip address located at the offset of the response
// print the correct auth based off of aa flag
void get_ip(unsigned char *res, size_t *res_i, unsigned int aa);

// Given a response and starting location
// Read the response and append it to the given string 'name'
void add_word(unsigned char *res, size_t *res_i, char **name, size_t *name_len);

// This method will go through the RDATA and capture the name
// that is stored at the location beginning at res[*res_i}
// This will have to handle being redirected by pointers
char* get_name(unsigned char *res, size_t *res_i, unsigned int aa, unsigned short rd_len);

// Skips past the question in the response packet.
// Updates res_i past the question and to the start of the answer.
// If the res_i pointer is not at the end of the header/start of the 
// question, return -1.
// If the request packet and the response packet's names don't match,
// return -2.
// return 0 on success.
int check_question(unsigned char *res, size_t res_len, size_t *res_i);

// Deconstructs and intreprets a dns response packet.
// Prints the answers in the dns response to stdout if everything checks out.
//
// The param res should be a pointer to a response packet.
// The param res_len must be an int pointer to the length of the response packet.
//
// returns -1, invalid input; null pointers
// returns -2, invalid header
int print_dns_response(unsigned char *res, size_t res_len);

#endif

