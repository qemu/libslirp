/* SPDX-License-Identifier: BSD-3-Clause */
#include "slirp.h"

struct capture {
    uint8_t packet[2048];
    size_t len;
};

static uint8_t guest_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x0f };

static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    struct capture *capture = opaque;

    g_assert_cmpuint(len, <=, sizeof(capture->packet));
    memcpy(capture->packet, buf, len);
    capture->len = len;
    return len;
}

static int64_t clock_ns(void *opaque) { return 0; }
static void timer_mod(void *timer, int64_t expire, void *opaque) { }
static SlirpCb callbacks = {
    .send_packet = send_packet,
    .clock_get_ns = clock_ns,
    .timer_mod = timer_mod,
};

static void check_source(struct capture *capture, const uint8_t *expected,
                         uint16_t protocol)
{
    g_assert_cmpuint(capture->len, >=, ETH_HLEN);
    g_assert_cmpmem(capture->packet + ETH_ALEN, ETH_ALEN, expected, ETH_ALEN);
    g_assert_cmpuint(capture->packet[12], ==, protocol >> 8);
    g_assert_cmpuint(capture->packet[13], ==, protocol & 0xff);
}

static void check_arp_reply(Slirp *s, struct capture *capture,
                            struct in_addr target, const uint8_t *expected)
{
    uint8_t packet[ETH_HLEN + sizeof(struct slirp_arphdr)] = { 0 };
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct slirp_arphdr *arp = (struct slirp_arphdr *)(packet + ETH_HLEN);

    memset(eth->h_dest, 0xff, ETH_ALEN);
    memcpy(eth->h_source, guest_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);
    arp->ar_hrd = htons(1);
    arp->ar_pro = htons(ETH_P_IP);
    arp->ar_hln = ETH_ALEN;
    arp->ar_pln = 4;
    arp->ar_op = htons(ARPOP_REQUEST);
    memcpy(arp->ar_sha, guest_mac, ETH_ALEN);
    arp->ar_sip = htonl(0x0a00020f);
    arp->ar_tip = target.s_addr;
    capture->len = 0;
    slirp_input(s, packet, sizeof(packet));
    check_source(capture, expected, ETH_P_ARP);
    g_assert_cmpuint(capture->len, >=, sizeof(packet));
    arp = (struct slirp_arphdr *)(capture->packet + ETH_HLEN);
    g_assert_cmpuint(ntohs(arp->ar_op), ==, ARPOP_REPLY);
    g_assert_cmpmem(arp->ar_sha, ETH_ALEN, expected, ETH_ALEN);
    g_assert_cmphex(arp->ar_sip, ==, target.s_addr);
}

static void check_ipv4(Slirp *s, struct capture *capture, const uint8_t *expected)
{
    struct mbuf *m = m_get(s);
    struct ip *ip = mtod(m, struct ip *);
    struct slirp_arphdr *arp;

    memset(ip, 0, sizeof(*ip));
    ip->ip_v = IPVERSION;
    ip->ip_src = s->vhost_addr;
    ip->ip_dst.s_addr = htonl(0x0a00024d);
    m->m_len = sizeof(*ip);
    capture->len = 0;
    g_assert_cmpint(if_encap(s, m), ==, 0);
    check_source(capture, expected, ETH_P_ARP);
    g_assert_cmpuint(capture->len, >=, ETH_HLEN + sizeof(*arp));
    arp = (struct slirp_arphdr *)(capture->packet + ETH_HLEN);
    g_assert_cmpuint(ntohs(arp->ar_op), ==, ARPOP_REQUEST);
    g_assert_cmpmem(arp->ar_sha, ETH_ALEN, expected, ETH_ALEN);
    g_assert_cmphex(arp->ar_sip, ==, s->vhost_addr.s_addr);
    arp_table_add(s, ip->ip_dst.s_addr, guest_mac);
    capture->len = 0;
    g_assert_cmpint(if_encap(s, m), ==, 1);
    check_source(capture, expected, ETH_P_IP);
    g_assert_cmpmem(capture->packet, ETH_ALEN, guest_mac, ETH_ALEN);
    m_free(m);
}

static void check_ndp(struct capture *capture, const uint8_t *expected,
                      uint8_t type, size_t header_len, uint8_t option_type)
{
    size_t offset = ETH_HLEN + sizeof(struct ip6);

    check_source(capture, expected, ETH_P_IPV6);
    g_assert_cmpuint(capture->len, >=, offset + header_len + NDPOPT_LINKLAYER_LEN);
    g_assert_cmpuint(capture->packet[offset], ==, type);
    offset += header_len;
    g_assert_cmpuint(capture->packet[offset], ==, option_type);
    g_assert_cmpuint(capture->packet[offset + 1], ==, NDPOPT_LINKLAYER_LEN / 8);
    g_assert_cmpmem(capture->packet + offset + 2, ETH_ALEN, expected, ETH_ALEN);
}

static void check_ipv6(Slirp *s, struct capture *capture, struct in6_addr source,
                       const uint8_t *expected)
{
    struct in6_addr guest = s->vhost_addr6;
    struct mbuf *m = m_get(s);
    struct ip6 *ip = mtod(m, struct ip6 *);
    struct icmp6 *icmp;

    guest.s6_addr[15] = 15;
    ndp_table_add(s, guest, guest_mac);
    memset(ip, 0, sizeof(*ip));
    ip->ip_v = IP6VERSION;
    ip->ip_src = source;
    ip->ip_dst = guest;
    m->m_len = sizeof(*ip);
    capture->len = 0;
    g_assert_cmpint(if_encap(s, m), ==, 1);
    check_source(capture, expected, ETH_P_IPV6);
    g_assert_cmpmem(capture->packet, ETH_ALEN, guest_mac, ETH_ALEN);
    m_free(m);

    /* Feed a valid neighbor solicitation and inspect the advertisement. */
    m = m_get(s);
    memset(m->m_data, 0, 2 + ETH_HLEN + sizeof(*ip) + ICMP6_NDP_NS_MINLEN);
    memcpy(m->m_data + 2 + ETH_ALEN, guest_mac, ETH_ALEN);
    m->m_data += 2 + ETH_HLEN;
    m->m_len = sizeof(*ip) + ICMP6_NDP_NS_MINLEN;
    ip = mtod(m, struct ip6 *);
    ip->ip_v = IP6VERSION;
    ip->ip_src = guest;
    ip->ip_dst = source;
    ip->ip_hl = 255;
    ip->ip_nh = IPPROTO_ICMPV6;
    ip->ip_pl = htons(ICMP6_NDP_NS_MINLEN);
    icmp = (struct icmp6 *)(ip + 1);
    icmp->icmp6_type = ICMP6_NDP_NS;
    icmp->icmp6_nns.target = source;
    icmp->icmp6_cksum = ip6_cksum(m);
    capture->len = 0;
    icmp6_input(m);
    check_ndp(capture, expected, ICMP6_NDP_NA, ICMP6_NDP_NA_MINLEN,
              NDPOPT_LINKLAYER_TARGET);
}

static void check_mode(unsigned int version, const uint8_t *configured)
{
    const uint8_t host4[ETH_ALEN] = { 0x52, 0x55, 10, 0, 2, 2 };
    const uint8_t dns4[ETH_ALEN] = { 0x52, 0x55, 10, 0, 2, 3 };
    const uint8_t host6[ETH_ALEN] = { 0x52, 0x56, 0, 0, 0, 2 };
    const uint8_t dns6[ETH_ALEN] = { 0x52, 0x56, 0, 0, 0, 3 };
    const uint8_t *shared = version >= 7 ? configured : NULL;
    struct capture capture = { 0 };
    SlirpConfig cfg = {
        .version = version,
        .in_enabled = true,
        .vnetwork.s_addr = htonl(0x0a000200),
        .vnetmask.s_addr = htonl(0xffffff00),
        .vhost.s_addr = htonl(0x0a000202),
        .vnameserver.s_addr = htonl(0x0a000203),
        .vprefix_len = 64,
    };
    Slirp *s;

    cfg.vprefix_addr6.s6_addr[0] = 0xfd;
    cfg.vhost6 = cfg.vnameserver6 = cfg.vprefix_addr6;
    cfg.vhost6.s6_addr[15] = 2;
    cfg.vnameserver6.s6_addr[15] = 3;
    if (configured) {
        memcpy(cfg.shared_mac, configured, ETH_ALEN);
    }
    s = slirp_new(&cfg, &callbacks, &capture);
    g_assert_nonnull(s);
    /* The stack must not retain a pointer into the caller's configuration. */
    memset(cfg.shared_mac, 0xcc, ETH_ALEN);

    check_arp_reply(s, &capture, cfg.vhost, shared ? shared : host4);
    check_arp_reply(s, &capture, cfg.vnameserver, shared ? shared : dns4);
    check_ipv4(s, &capture, shared ? shared : host4);
    check_ipv6(s, &capture, cfg.vhost6, shared ? shared : host6);
    check_ipv6(s, &capture, cfg.vnameserver6, shared ? shared : dns6);
    capture.len = 0;
    ndp_send_ns(s, cfg.vnameserver6);
    check_ndp(&capture, shared ? shared : host6, ICMP6_NDP_NS,
              ICMP6_NDP_NS_MINLEN, NDPOPT_LINKLAYER_SOURCE);
    capture.len = 0;
    ra_timer_handler(s, NULL);
    check_ndp(&capture, shared ? shared : host6, ICMP6_NDP_RA,
              ICMP6_NDP_RA_MINLEN, NDPOPT_LINKLAYER_SOURCE);
    slirp_cleanup(s);
}

int main(int argc, char **argv)
{
    const uint8_t vbox[ETH_ALEN] = { 0x52, 0x54, 0, 0x12, 0x35, 0 };
    const uint8_t custom[ETH_ALEN] = { 0x02, 0xab, 0xcd, 0xef, 0x12, 0x34 };
    const uint8_t multicast[ETH_ALEN] = { 0x01, 0, 0x5e, 0, 0, 1 };
    SlirpConfig cfg = { .version = SLIRP_CONFIG_VERSION_MAX };

    g_test_init(&argc, &argv, NULL);
    check_mode(SLIRP_CONFIG_VERSION_MAX, NULL);
    check_mode(SLIRP_CONFIG_VERSION_MAX, vbox);
    check_mode(SLIRP_CONFIG_VERSION_MAX, custom);
    check_mode(6, custom);
    check_mode(6, multicast);
    memcpy(cfg.shared_mac, multicast, ETH_ALEN);
    g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "*shared_mac*");
    g_assert_null(slirp_new(&cfg, &callbacks, NULL));
    g_test_assert_expected_messages();
    memset(cfg.shared_mac, 0xff, ETH_ALEN);
    g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "*shared_mac*");
    g_assert_null(slirp_new(&cfg, &callbacks, NULL));
    g_test_assert_expected_messages();
    return 0;
}
