/*    Copyright (C) 2022  Robert Caamano   */
/*
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.

 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *   see <https://www.gnu.org/licenses/>.
*/

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bcc/bcc_common.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <stdbool.h>
#include <linux/if.h>

#ifndef memcpy
 #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif
#define BPF_MAP_ID_DIAG_MAP     5
#define BPF_MAP_ID_TUN_MAP      9
#define BPF_MAP_ID_IFINDEX_TUN  10
#define MAX_IF_ENTRIES          30
#define BPF_MAX_SESSIONS        10000

/*Key to tun_map, tcp_map and udp_map*/
struct tuple_key {
    __u32 daddr;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
};

/*Key to tun_map*/
struct tun_key {
    __u32 daddr;
    __u32 saddr;
};

/*Value to tun_map*/
struct tun_state {
    unsigned long long tstamp;
    unsigned int ifindex;
    unsigned char source[6];
    unsigned char dest[6];
};

/*value to ifindex_tun_map*/
struct ifindex_tun {
    uint32_t index;
    char ifname[IFNAMSIZ];
    char cidr[16];
    char mask[3];
    bool verbose;
};

/*tun ifindex map*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(id, BPF_MAP_ID_IFINDEX_TUN);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct ifindex_tun));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_tun_map SEC(".maps");

/*Hashmap to track tun interface inbound passthrough connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(id, BPF_MAP_ID_TUN_MAP);
     __uint(key_size, sizeof(struct tun_key));
     __uint(value_size,sizeof(struct tun_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_map SEC(".maps");

static inline struct tun_state *get_tun(struct tun_key key){
    struct tun_state *ts;
    ts = bpf_map_lookup_elem(&tun_map, &key);
	return ts;
}

/*get entry from tun ifindex map*/
static inline struct ifindex_tun *get_tun_index(uint32_t key){
    struct ifindex_tun *iftun; 
    iftun = bpf_map_lookup_elem(&ifindex_tun_map, &key);
	return iftun;
}


SEC("xdp_redirect")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    /*look up attached interface inbound diag status*/
    struct ifindex_tun *tun_diag = get_tun_index(0);
    if (!tun_diag)
    {
        return XDP_PASS;
    }  
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(ctx->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)ctx->data_end){
            return XDP_PASS;
    }
    struct iphdr *iph = (struct iphdr *)(unsigned long)(ctx->data);
    /* ensure ip header is in packet bounds */
    if ((unsigned long)(iph + 1) > (unsigned long)ctx->data_end){
            return XDP_PASS;
    }
    /* ip options not allowed */
    if (iph->ihl != 5){
        //bpf_printk("no options allowed");
            return XDP_PASS;
    }
    struct tun_key tun_state_key;
    tun_state_key.daddr = iph->saddr;
    tun_state_key.saddr = iph->daddr;
    struct tun_state *tus = get_tun(tun_state_key);
    if(tus){
        bpf_xdp_adjust_head(ctx, -14);
        struct ethhdr *eth = (struct ethhdr *)(unsigned long)(ctx->data);
        /* verify its a valid eth header within the packet bounds */
        if ((unsigned long)(eth + 1) > (unsigned long)ctx->data_end){
                return XDP_PASS;
        }
        struct iphdr *iph = (struct iphdr *)(ctx->data + sizeof(*eth));
        /* ensure ip header is in packet bounds */
        if ((unsigned long)(iph + 1) > (unsigned long)ctx->data_end){
                return XDP_PASS;
        }
        /* ip options not allowed */
        if (iph->ihl != 5){
            //bpf_printk("no options allowed");
                return XDP_PASS;
        }
        
        if(tun_diag->verbose){      
            bpf_printk("state found!\n");
            bpf_printk("saddr=%x\n", iph->saddr);
            bpf_printk("daddr=%x\n", iph->daddr);
            bpf_printk("insert smac=%x\n", tus->dest);
            bpf_printk("insert dmac=%x\n", tus->source);
            bpf_printk("Redirect=%d\n", tus->ifindex);
        }
        
        memcpy(&eth->h_dest, &tus->source,6);
        memcpy(&eth->h_source, &tus->dest,6);
        unsigned short proto = bpf_htons(ETH_P_IP);
        memcpy(&eth->h_proto, &proto, sizeof(proto));
        return bpf_redirect(tus->ifindex,0);
    }
    if(tun_diag->verbose){
        bpf_printk("no matching state found!\n");
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
