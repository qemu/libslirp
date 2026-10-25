/* SPDX-License-Identifier: BSD-3-Clause */
#include "slirp.h"

static unsigned int replies;
static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    const struct ethhdr *eth = buf;
    if (eth->h_proto == htons(ETH_P_ARP)) {
        replies++;
    }
    return len;
}
static SlirpCb callbacks = { .send_packet = send_packet };

static void arp_request(Slirp *s, struct in_addr target)
{
    uint8_t packet[sizeof(struct ethhdr) + sizeof(struct slirp_arphdr)] = { 0 };
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct slirp_arphdr *arp = (struct slirp_arphdr *)(eth + 1);

    memset(eth->h_dest, 0xff, ETH_ALEN);
    eth->h_source[0] = 0x52;
    eth->h_source[5] = 1;
    eth->h_proto = htons(ETH_P_ARP);
    arp->ar_hrd = htons(1);
    arp->ar_pro = htons(ETH_P_IP);
    arp->ar_hln = ETH_ALEN;
    arp->ar_pln = 4;
    arp->ar_op = htons(ARPOP_REQUEST);
    memcpy(arp->ar_sha, eth->h_source, ETH_ALEN);
    arp->ar_sip = htonl(0x0a00020f);
    arp->ar_tip = target.s_addr;
    slirp_input(s, packet, sizeof(packet));
}

int main(void)
{
    struct ip4_lomap entries[] = {
        { .loaddr.s_addr = htonl(0x7f000002), .vaddr.s_addr = htonl(0x0a000304) },
        { .loaddr.s_addr = htonl(0x7f000003), .vaddr.s_addr = htonl(0x0a000404) },
    };
    struct ip4_lomap_desc map = { entries, G_N_ELEMENTS(entries) };
    SlirpConfig cfg = {
        .version = SLIRP_CONFIG_VERSION_MAX,
        .in_enabled = true,
        .vnetwork.s_addr = htonl(0x0a000000),
        .vnetmask.s_addr = htonl(0xffff0000),
        .vhost.s_addr = htonl(0x0a000002),
        .loopback_map = &map,
    };
    Slirp *s = slirp_new(&cfg, &callbacks, NULL);
    struct socket so = { .slirp = s };
    struct sockaddr_storage storage = { .ss_family = AF_INET };
    struct sockaddr_in *addr = (struct sockaddr_in *)&storage;

    g_assert_nonnull(s);
    g_assert_true(s->loopback_map != entries);
    for (unsigned int i = 0; i < G_N_ELEMENTS(entries); i++) {
        so.so_faddr = entries[i].vaddr;
        addr->sin_addr = so.so_faddr;
        g_assert_cmpint(sotranslate_out(&so, &storage), ==, 0);
        g_assert_cmphex(addr->sin_addr.s_addr, ==, entries[i].loaddr.s_addr);
        arp_request(s, entries[i].vaddr);
    }
    g_assert_cmpuint(replies, ==, 2);
    so.so_faddr.s_addr = htonl(0x0a000504);
    addr->sin_addr = so.so_faddr;
    g_assert_cmpint(sotranslate_out(&so, &storage), ==, 0);
    g_assert_cmphex(addr->sin_addr.s_addr, ==, so.so_faddr.s_addr);
    arp_request(s, so.so_faddr);
    g_assert_cmpuint(replies, ==, 2);
    slirp_cleanup(s);
    cfg.disable_host_loopback = true;
    s = slirp_new(&cfg, &callbacks, NULL);
    g_assert_cmpuint(s->loopback_map_len, ==, 0);
    arp_request(s, entries[0].vaddr);
    g_assert_cmpuint(replies, ==, 2);
    slirp_cleanup(s);
    cfg.version = 6;
    s = slirp_new(&cfg, &callbacks, NULL);
    g_assert_cmpuint(s->loopback_map_len, ==, 0);
    slirp_cleanup(s);
    return 0;
}
