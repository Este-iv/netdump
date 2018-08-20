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
// This is to simplify the bit minipulation
struct APR_info{
  u_char hrdwr_type, protocol_type;
  u_char Shardware_add[6], Sprotocol_add[4], Target_add[6], Target_Proto[4];
  u_int16_t hardware_Len, protcol_Len;
  u_int16_t Oper;
};

struct TCP_info{
  u_int32_t seq_num;
  u_int32_t ack_num;
  u_int16_t urp;
  u_int16_t win,chksum;
  u_int16_t src, dest; 
  u_int16_t res:4, _soff:4;
  u_int16_t  fn:1, sy:1, rs:1, ack:1, ug:1, ps:1;
};

struct ICMP_info{
  u_int8_t type;
  u_int8_t c;
  u_int16_t _check;
};

struct IP_info {
  u_int8_t  type;
  u_int8_t ver: 4, leng:4;
  u_int8_t proto;
  u_char source_add[4],dest_add[4];
  u_int8_t ttl;
  u_int16_t t_l ,ID,frag, chk;
  u_int16_t id_type;

};


// creation of classes to be used in netdump.c

void ARP_data(const u_char *p, u_int caplen, struct APR_info *arp); 
void Declrations(const u_char *p, u_int caplen); 
void IP_BASE(const u_char *p, u_int caplen, struct IP_info *ip);

#endif
