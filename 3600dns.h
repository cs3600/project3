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

// Represents the requested server ip,
// port number, and domain name in a
// logical structure.
typedef struct request_options_t {
	// server ip address
	// 2^32 ip addresses in IPv4
	// 255.255.255.255/0, 16 bits worst case
	char server[16];
	// the port number
	// 2^16 ports
	short port;
	// the domain name
	// technically could be infinitely long
	char *name;
} request_options;

#endif

