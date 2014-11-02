/*
 * CS3600, Spring 2014
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__
#define ID 1337 // Default query id to use
#define PORT 53 // Default udp port for DNS
#define BYTE_TO_BITS 8 // The number of bits in a byte
#define FLAG_SIZE 16 // The number of bits in the flag segment of a packet
#define FLAG_CODE 256 // The default flag code for queries in decimal

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

