// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define LIBBPF_PIN_BY_NAME 1

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct block_entry {
    __u64 blocked_at_ns;
    __u64 dropped_pkts;
    __u64 dropped_bytes;
    __u32 reason_code;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;

SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *nh = eth + 1;

    if (h_proto == __constant_htons(ETH_P_8021Q) ||
        h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr = nh;
        if ((void *)(vhdr + 1) > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
        nh = vhdr + 1;
    }

    if (h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = nh;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u64 pkt_bytes = (__u64)((char *)data_end - (char *)data);

    __u32 saddr = iph->saddr;
    struct block_entry *e = bpf_map_lookup_elem(&blocked_ips, &saddr);
    if (!e) {
        __u32 daddr = iph->daddr;
        e = bpf_map_lookup_elem(&blocked_ips, &daddr);
    }

    if (e) {
        __sync_fetch_and_add(&e->dropped_pkts, 1);
        __sync_fetch_and_add(&e->dropped_bytes, pkt_bytes);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
