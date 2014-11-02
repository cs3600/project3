/*
 * CS3600, Spring 2014
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__
#define ID 1337 // Default query id to use

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
	// 65535/0, 6 bits worst case
	char port[6];
	// the domain name
	// technically could be infinitely long
	char *name;
} request_options;

#endif

