#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#define IP_MF		0x2000	/* "More Fragments" */
#define IP_OFFSET	0x1fff	/* "Fragment Offset" */
#define MAX_PKT_LEN 0xffff
#define WINDOW_LEN 256
#define KW_LEN 4
static const char blocked_kw[KW_LEN] = "flag";
static const char blocked_char = '%';

struct kw_scan_ctx {
    struct __sk_buff *skb;
    __u32 off;
    __u32 len;
    __u32 found;
};


static long kw_scan_cb(__u32 idx, void *data)
{
    struct kw_scan_ctx *ctx = data;
    unsigned char buf[KW_LEN];

    // We guarantee idx + KW_LEN <= ctx->len from the caller, so no extra
    // bounds check is needed here for the packet.
     
    if (bpf_skb_load_bytes(ctx->skb, ctx->off + idx, buf, KW_LEN) < 0) {
        // Treat load error as found kw
        ctx->found = 1;
        return 1;
    }

    if (__builtin_memcmp(buf, blocked_kw, KW_LEN) == 0) {
        ctx->found = 1;
        return 1;
    }

    return 0;
}

__u32 __always_inline has_blocked_kw(struct __sk_buff *skb, __u32 off, __u32 len)
{
    if (off > MAX_PKT_LEN || off + len > MAX_PKT_LEN || len >= MAX_PKT_LEN)
        return 1;
    
    // Cannot match when length is shorter than KW_LEN
    if (len < KW_LEN) {
        return 0;
    }

    struct kw_scan_ctx ctx = {
        .skb   = skb,
        .off   = off,
        .len   = len,
        .found = 0,
    };

    // Use bpf_loop to make verifier happy
    __u32 nr_loops = len - KW_LEN + 1;

    long ret = bpf_loop(nr_loops, kw_scan_cb, &ctx, 0);
    if (ret < 0) {
        return 1;
    }

    return ctx.found ? 1 : 0;
}

static long char_scan_cb(__u32 idx, void *data)
{
    struct kw_scan_ctx *ctx = data;
    unsigned char buf[1];
     
    if (bpf_skb_load_bytes(ctx->skb, ctx->off + idx, buf, 1) < 0) {
        // Treat load error as found kw
        ctx->found = 1;
        return 1;
    }

    if (buf[0] == blocked_char) {
        ctx->found = 1;
        return 1;
    }

    return 0;
}


__u32 __always_inline has_blocked_char(struct __sk_buff *skb, __u32 off, __u32 len)
{
    if (off > MAX_PKT_LEN || off + len > MAX_PKT_LEN || len >= MAX_PKT_LEN)
        return 1;
    
    if (len < 1)
        return 0;

    struct kw_scan_ctx ctx = {
        .skb   = skb,
        .off   = off,
        .len   = len,
        .found = 0,
    };

    // Use bpf_loop to make verifier happy
    __u32 nr_loops = len;

    long ret = bpf_loop(nr_loops, char_scan_cb, &ctx, 0);
    if (ret < 0) {
        return 1;
    }

    return ctx.found ? 1 : 0;
}

SEC("tc/ingress")
int firewall_in(struct __sk_buff *skb) {
    void *data = (void *)(__u64)skb->data;
    void *data_end = (void *)(__u64)skb->data_end;
    
    // L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_UNSPEC;
    }
    
    // Handle IPv4
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr * iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_UNSPEC;
        }
        if (iph->version != 4) {
            return TC_ACT_UNSPEC;
        }
        __u32 ip_hdr_size = (iph->ihl & 0x0F) << 2;
        if (ip_hdr_size < sizeof(*iph)) {
            return TC_ACT_UNSPEC;
        }
        if ((void *)iph + ip_hdr_size > data_end) {
            return TC_ACT_UNSPEC;
        }
        // Only allow a single fragment
        if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
            return TC_ACT_SHOT;
        }
        // Only care about TCP
        if (iph->protocol != IPPROTO_TCP) {
            return TC_ACT_UNSPEC;
        }
        __u16 ip_tot_len = bpf_ntohs(iph->tot_len);
        if (ip_hdr_size > ip_tot_len) {
            return TC_ACT_UNSPEC;
        }

        // Filter traffic
        if (has_blocked_kw(skb, ETH_HLEN + ip_hdr_size, ip_tot_len - ip_hdr_size)) {
            return TC_ACT_SHOT;
        }
        if (has_blocked_char(skb, ETH_HLEN + ip_hdr_size, ip_tot_len - ip_hdr_size)) {
            return TC_ACT_SHOT;
        }


        return TC_ACT_OK;
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        // No IPv6
        return TC_ACT_SHOT;
    }
    
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
