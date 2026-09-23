/* SPDX-License-Identifier: BSD-3-Clause */
#include "slirp.h"
#include "dhcpv6.h"

static uint8_t reply[65536];
static size_t reply_len;
static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    g_assert_cmpuint(len, <=, sizeof(reply));
    memcpy(reply, buf, len);
    reply_len = len;
    return len;
}
static int64_t clock_ns(void *opaque) { return 0; }
static void timer_mod(void *timer, int64_t expire, void *opaque) { }
static SlirpCb callbacks = {
    .send_packet = send_packet,
    .clock_get_ns = clock_ns,
    .timer_mod = timer_mod,
};

int main(void)
{
    struct in6_addr addrs[200];
    SlirpConfig cfg = {
        .version = SLIRP_CONFIG_VERSION_MAX,
        .if_mtu = 1280,
        .advertised_nameservers6 = addrs,
        .advertised_nameservers6_len = G_N_ELEMENTS(addrs),
    };
    struct sockaddr_in6 guest = { .sin6_family = AF_INET6, .sin6_port = htons(546) };
    uint8_t mac[ETH_ALEN] = { 0x52, 0x54, 0, 0, 0, 1 };
    const uint8_t request[] = { 11, 1, 2, 3, 0, 6, 0, 2, 0, 23 };
    struct mbuf *m;
    Slirp *s;
    unsigned int size;
    size_t off;

    for (unsigned int i = 0; i < G_N_ELEMENTS(addrs); i++) {
        memset(&addrs[i], 0, sizeof(addrs[i]));
        addrs[i].s6_addr[0] = 0x20;
        addrs[i].s6_addr[1] = 1;
        addrs[i].s6_addr[15] = i;
    }
    guest.sin6_addr.s6_addr[0] = 0xfd;
    guest.sin6_addr.s6_addr[15] = 15;
    s = slirp_new(&cfg, &callbacks, NULL);
    ndp_table_add(s, guest.sin6_addr, mac);
    m = m_get(s);
    memset(m->m_data, 0, sizeof(struct udphdr));
    memcpy(m->m_data + sizeof(struct udphdr), request, sizeof(request));
    m->m_len = sizeof(struct udphdr) + sizeof(request);
    dhcpv6_input(&guest, m);
    m_free(m);
    g_assert_cmpuint(reply_len, <=, ETH_HLEN + cfg.if_mtu);
    off = ETH_HLEN + sizeof(struct ip6) + sizeof(struct udphdr) + 4;
    g_assert_cmpuint(reply_len, >, off + 4);
    g_assert_cmpuint(reply[off + 1], ==, 23);
    size = (reply[off + 2] << 8) | reply[off + 3];
    g_assert_cmpuint(size, ==, ((1280 - 40 - 8 - 4 - 4) / 16) * 16);
    g_assert_cmpmem(reply + off + 4, size, addrs, size);
    ra_timer_handler(s, NULL);
    g_assert_cmpuint(reply_len, <=, ETH_HLEN + cfg.if_mtu);
    off = ETH_HLEN + sizeof(struct ip6) + ICMP6_NDP_RA_MINLEN +
          NDPOPT_LINKLAYER_LEN + NDPOPT_PREFIXINFO_LEN;
    g_assert_cmpuint(reply[off], ==, NDPOPT_RDNSS);
    size = reply[off + 1] * 8 - NDPOPT_RDNSS_HEADER_LEN;
    g_assert_cmpuint(size, >, 0);
    g_assert_cmpuint(size, <, sizeof(addrs));
    g_assert_cmpmem(reply + off + NDPOPT_RDNSS_HEADER_LEN, size, addrs, size);
    slirp_cleanup(s);
    return 0;
}
