/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

 /*returns the route using longest prefix matching*/
struct sr_rt* longest_prefix_matching(struct sr_instance* sr, uint32_t dest){

    struct sr_rt* current = sr->routing_table;
    struct sr_rt* match = NULL;
    unsigned long longest_match = 0;
    struct in_addr dest_addr;
    dest_addr.s_addr = dest;

    while(current != NULL){ /*while there are still entries in the routing table*/
        if (((dest_addr.s_addr & current->mask.s_addr) == (current->dest.s_addr & current->mask.s_addr)) & (longest_match <= current->mask.s_addr)){
            longest_match = current->mask.s_addr;
            match = current;
        }
        current = current->next;
    }
    return match;

}


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
    time_t currtime = time(NULL);

    if (difftime(currtime, req->sent) > 1.0){
        if (req->times_sent >= 5){
            /*send icmp host unreachable to source addr of all pkts waiting on req
            /will use method defined in sr_router.c*/
            sr_arpreq_destroy(&sr, req);
        }
        else{
            /*send arp request*/

            struct sr_rt* rt_entry = longest_prefix_matching(sr, req->ip);
            struct sr_if* sr_interface = sr_get_interface(sr, req->packets->iface);

            struct sr_arpentry* existing_arp = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);

            sr_arp_hdr_t* arp_header = (struct sr_arp_hdr*)malloc(sizeof(struct sr_arp_hdr));
            /*fill out the arp header*/
            arp_header->ar_hrd = htons(arp_hrd_ethernet);             /* format of hardware address   */
            arp_header->ar_pro = htons(ethertype_ip);             /* format of protocol address   */
            arp_header->ar_hln = ETHER_ADDR_LEN;             /* length of hardware address   */
            arp_header->ar_pln = sizeof(uint32_t);             /* length of protocol address   */
            arp_header->ar_op = htons(arp_op_request);              /* ARP opcode (command)         */
            memcpy(arp_header->ar_sha, sr_interface->addr, ETHER_ADDR_LEN);   /* sender hardware address      */
            arp_header->ar_sip = sr_interface->ip;             /* sender IP address            */
            /*arp_header->ar_tha[ETHER_ADDR_LEN];   /* target hardware address *IGNORE FOR ARP      */
            arp_header->ar_tip = req->ip;

            /*send the packet*/
            direct_and_send_packet(sr, arp_header, req->ip);

            req->sent = currtime;
            req->times_sent++;
        }
    }

}
  
/*construct an ICMP echo message and send it*/
void send_icmp_echo(struct sr_instance* sr, sr_ip_hdr_t* packet){

    /*initialise the icmp packet header*/
    sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*) ((uint8_t*)packet + 4*packet->ip_hl);

    /*switch the destination and source addresses around*/
    uint32_t src = packet->ip_src;
    uint32_t dest = packet->ip_dst;
    packet->ip_src = dest;
    packet->ip_dst = src;

    /*icmp message type 0, code 0*/
    icmp_header->icmp_type = 0;
    icmp_header->icmp_type = 0;

    /*get the checksum calculated and put into the header*/
    packet->ip_sum = 0;
    packet->ip_sum = cksum(packet, 32);
    /*send the packet*/
    direct_and_send_packet(sr, packet, src);

}

void send_icmp_message(struct sr_instance* sr, sr_ip_hdr_t* packet, int type, int code){

}

void send_arp_reply(){

}

/*directs to the packet to appropriate ARP queue or sends it*/
void direct_and_send_packet(struct sr_instance* sr, uint8_t* packet, uint32_t destination){

    /*first, check the routing table to see if a valid route is available*/
    struct sr_rt* valid_rt = longest_prefix_matching(sr, destination);
    
    if (valid_rt == NULL){ /*no valid route is returned*/
        send_icmp_message(sr, packet, 3, 0); /*send ICMP message unreachable destination*/
        return;
    }

    /*if it does exist, check the ARP cache for a matching IP->MAC address*/
    struct sr_arpentry* existing_arp = sr_arpcache_lookup(&sr->cache, valid_rt->gw.s_addr);
    /*grab the interface for that existing_arp as well*/
    struct sr_if* interface = sr_get_interface(sr, valid_rt->interface);

    if(existing_arp){ /*if there is an existing ARP reply with matching IP->MAC address, use that MAC address to send the packet*/

        /*initialise ethernet header and ethernet packet*/
        struct sr_ethernet_hdr ethernet_header;
        uint8_t* ethernet_packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(packet));

        memcpy(ethernet_header.ether_dhost, existing_arp->mac, ETHER_ADDR_LEN);
        memcpy(ethernet_header.ether_shost, interface->addr, ETHER_ADDR_LEN);

        /*copy ethernet header into packet*/
        memcpy(ethernet_packet, &ethernet_header, sizeof(struct sr_ethernet_hdr));
        /*copy the ICMP packet into the mem address after the header*/
        memcpy((ethernet_packet + sizeof(struct sr_ethernet_hdr)), packet, sizeof(packet));

        sr_send_packet(sr, ethernet_packet, sizeof(packet) + sizeof(struct sr_ethernet_hdr), valid_rt->interface);

        free(ethernet_packet);

    }else{ /*if there is no existing ARP in the cache with matching IP->MAC address, set up an ARP request then put it in the queue*/

        /*make a copy of the packet*/
        uint8_t* copy = packet;
        /*throw it in the arp queue*/
        struct sr_arpreq* arp_request = sr_arpcache_queuereq(&sr->cache, valid_rt->gw.s_addr, copy, sizeof(packet), valid_rt->interface);
        handle_arpreq(sr, arp_request);

    }

}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* TODO: (opt) Add initialization code here */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("Length of packet GET:  %d\n",len);

  /* TODO: Add forwarding logic here */
  struct sr_if* received_if = sr_get_interface(sr, interface);
  struct sr_ethernet_hdr* received_ethernet_hdr = (struct sr_ethernet_hdr*)packet;

    switch (htons(received_ethernet_hdr->ether_type))
    {
        /*case ETHERTYPE_ARP:
            handle_arp_packet(sr, packet, len, received_if, received_ethernet_hdr);
            break;*/

        /*case ETHERTYPE_IP:
            handle_ip_packet(sr, packet, len, received_if, received_ethernet_hdr);
            break;*/

        default:
            printf("\nReceived Unknow Packet, length = %d\n", len);
            break;
    }
}/* -- sr_handlepacket -- */


void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* received_if, struct sr_ethernet_hdr* received_e_hdr)
{
    printf("\nReceived IP Packet, length = %d\n", len);


    struct sr_ethernet_hdr* output_ethernet_hdr;
    output_ethernet_hdr = ((struct sr_ethernet_hdr*)(malloc(sizeof(struct sr_ethernet_hdr))));
    struct sr_icmp_hdr* received_icmp_hdr;
    struct sr_icmp_hdr* output_icmp_hdr;
    uint8_t* output_packet;
    int queue_index;

    /***** Getting the IP header *****/
    struct sr_ip_hdr* received_ip_hdr = ((struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr)));
    struct sr_ip_hdr* output_ip_hdr = ((struct sr_ip_hdr*)(malloc(sizeof(struct sr_ip_hdr))));

    /***** Checking the received Checksum *****/
    int received_sum_temp = received_ip_hdr->ip_sum;
    received_ip_hdr->ip_sum = 0;
    uint16_t received_sum = cksum(received_ip_hdr, sizeof(struct sr_ip_hdr));
    if (received_sum != received_sum_temp)
    {
        printf("Packet dropped due to invalid checksum\n");

        return;
    }

    received_ip_hdr->ip_ttl = received_ip_hdr->ip_ttl -1;

    received_ip_hdr->ip_sum = cksum(received_ip_hdr, sizeof(struct sr_ip_hdr));

    /***** Checking the received TTL *****/
    if (received_ip_hdr->ip_ttl < 0)
    {
        printf("-> Packet dropped: invalid TTL\n");
        /* TODO: send icmp error: (sr, packet, len, received_if, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);*/

        return;
    }

    int reached = -1;
    struct sr_if* temp_sr_if = received_if;

    while(temp_sr_if != NULL)
    {
       if (temp_sr_if->ip == received_ip_hdr->ip_dst)
       {
         reached = 0;
       }
    }
    if (reached != 0)
    {
        printf(" sending packet, length = %d\n", len);
        /* TODO: send to default next*/

        return;
    }

    if (received_ip_hdr->ip_p == ip_protocol_icmp)
    {
            /***** Getting the ICMP header *****/
	    received_icmp_hdr = ((struct sr_icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)));
            output_icmp_hdr = ((struct sr_icmp_hdr*)(malloc(sizeof(struct sr_icmp_hdr))));

            if ((received_icmp_hdr->icmp_type == ICMP_ECHO_REQUEST_TYPE) & (received_icmp_hdr->icmp_code == ICMP_ECHO_REQUEST_CODE))
            {
                printf("Requesting The IP Packet is ICMP ECHO \n");

                printf("Constructing ICMP ECHO REPLY Packet\n");
                int i;

                /* Destination address */
                for (i = 0; i < ETHER_ADDR_LEN; i++)
                {
                    output_ethernet_hdr->ether_dhost[i] = 255;
                }
		
                /* Source address */   
                for (i = 0; i < ETHER_ADDR_LEN; i++)
                {
                    output_ethernet_hdr->ether_shost[i] = ((uint8_t)(received_if->addr[i]));
                }         
                
                /* Type */
                output_ethernet_hdr->ether_type = received_e_hdr->ether_type;


                /* Version + Header length */
                output_ip_hdr->ip_v = received_ip_hdr->ip_v;
                output_ip_hdr->ip_hl = received_ip_hdr->ip_hl;

                /* DS */
                output_ip_hdr->ip_tos = received_ip_hdr->ip_tos;

                /* Total length */
                output_ip_hdr->ip_len = received_ip_hdr->ip_len;

                /* Identification */
                output_ip_hdr->ip_id = received_ip_hdr->ip_id;

                /* Fragment */
                output_ip_hdr->ip_off = received_ip_hdr->ip_off;

                /* TTL */
                output_ip_hdr->ip_ttl = 64;

                /* Protocol */
                output_ip_hdr->ip_p = received_ip_hdr->ip_p;

                /* Checksum */
                output_ip_hdr->ip_sum = 0;

                /* Source IP address */
                output_ip_hdr->ip_src = received_ip_hdr->ip_dst;

                /* Destination IP address */
                output_ip_hdr->ip_dst = received_ip_hdr->ip_src;

                /* Re-Calculate checksum of the IP header */
                output_ip_hdr->ip_sum = cksum(output_ip_hdr, sizeof(struct sr_ip_hdr));

                /* Type */
                output_icmp_hdr->icmp_type = ICMP_ECHO_REPLY_TYPE;

                /* Code */
                output_icmp_hdr->icmp_code = ICMP_ECHO_REPLY_CODE;

                /* Checksum */
                output_icmp_hdr->icmp_sum = 0;

                /***** Creating the transmitted packet *****/
                output_packet = ((uint8_t*)(malloc(sizeof(uint8_t) * len)));

                memcpy(output_packet, output_ethernet_hdr, sizeof(struct sr_ethernet_hdr));
                memcpy(output_packet + sizeof(struct sr_ethernet_hdr), output_ip_hdr, sizeof(struct sr_ip_hdr));
                memcpy(output_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), output_icmp_hdr, sizeof(struct sr_icmp_hdr));
                /* Copy the Data part */
		unsigned int i2;
                for (i2 = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr); i2 < len; i2++)
                {
                    output_packet[i2] = packet[i2];
                }


                /* Re-Calculate checksum of the ICMP header */
                /* Updating the new checksum in output_packet */
                ((struct sr_icmp_hdr*)(output_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)))->icmp_sum =
                    cksum(output_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), len - (sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)));


                /* TODO: send the out_packet out */


                    free(output_packet);
                }

                
                free(output_icmp_hdr);
                free(output_ip_hdr);
                free(output_ethernet_hdr);
            }
            else if ((received_icmp_hdr->icmp_type == ICMP_ECHO_REPLY_TYPE) & (received_icmp_hdr->icmp_code == ICMP_ECHO_REPLY_CODE))
            {
                printf("-> Get the reply successfully\n");
            }
}/* end handle_ip_packet */
