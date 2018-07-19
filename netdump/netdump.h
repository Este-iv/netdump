#ifndef NETDUMP_H
# define NETDUMP_H
// Original things from netdump.c
// purpose of this file is to simplify the work needed to be done.

/*Table,
u_int ->      4 bytes
u_int8_t  ->  8 bytes
u_int16_t -> 16 bytes
u_int32_t -> 32 bytes
....
and so on

*/

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
#define Operation_request 1
#define Operation_reply 2
#define NEW_SNAPLEN 1518
#define ETHERNET_STANDARD 14
#define ADDRESS_LENGTH 6
// struct implementation.
struct APR_info{
  // u_char hrdwr_type, protocol_type;
  // u_char SHA[], SPA[], THA[], TPA[]; // 6,4,6,4 ... why is it like this??
  // u_int16_t hardware_Len, protcol_Len;
}APR_t;

struct TCP_info{

}TCP_t;

struct ICMP_info{

}ICMP_t;

struct IP_info {
  u_int32_t sender, destination;
  // figure out the rest of these.. need to ask the discord chat.
  u_int8_t ;
  u_int16_t ;
}IP_t;

// there is all this sniff shit... what is that for?
// add it in later. I need to progress in the code to find out.

// creation of classes to be used in netdump.c
// add packet print shit in here?? or make another .h file?
void ethernet_data(const u_char* p, u_int size);



#endif
