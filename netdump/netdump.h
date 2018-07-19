#ifndef NETDUMP_H
# define NETDUMP_H
// Original things from netdump.c
// purpose of this file is to simplify the work needed to be done.

// #define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// Defining of variable.
#define ARP_things 1
#define ARP_stuff 2
#define NEW_SNAP 1518
#define ETHERNET_STANDARD 14
#define ADDRESS_LENGTH 6
// struct implementation.
// change the names on this thing.
struct Iheader {

};

struct APRheader{

};

struct TCPheader{

};

struct ICMPheader{

};
// there is all this sniff shit... what is that for?
// add it in later. 

// creation of classes to be used in netdump.c





#endif
