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
// Default QTYPE code
// Represents A records
#define QTYPE_CODE 1

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
	// server ip address
	// 2^32 ip addresses in IPv4
	// 255.255.255.255/0, 16 bits worst case
	char server[IP_LEN];
	// the port number
	// 2^16 ports
	unsigned short port;
	// the domain name
	// technically could be infinitely long
	char *name;
} request_options;

// Walk over a name segement to get res_i to point to next segment
void walk_name(unsigned char *res, int *res_i);

// Returns the Rcode from a given response flag grouping
void print_error_code(unsigned char rcode, unsigned char aa);

// Get an answer given res and the index into res (res_i)
void get_answer(unsigned char *res, int *res_i, unsigned int aa);

// Get the name at the given offset, should only be rd_len long
char* get_name(unsigned char *res, int *res_i, int rd_len, unsigned int aa);

// Get the ip address at the given offset of the response
char* get_ip(unsigned char *res, int *res_i, unsigned int aa);

// add the word at the given offset to the given name
void add_word(unsigned char *res, int *res_i, char **name, int *name_len);

// is the value at the given index in res a pointer
int is_pointer(unsigned char *res, int *res_i);
#endif

