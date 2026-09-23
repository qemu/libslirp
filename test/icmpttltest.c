/* SPDX-License-Identifier: BSD-3-Clause */
#include "slirp.h"
#ifndef _WIN32
#include <poll.h>
#endif

static unsigned int packets;
static uint8_t reply[2048];
static size_t reply_len;
static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    g_assert_cmpuint(len, <=, sizeof(reply));
    memcpy(reply, buf, len);
    reply_len = len;
    packets++;
    return len;
}
static void register_socket(slirp_os_socket fd, void *opaque) { }
static void unregister_socket(slirp_os_socket fd, void *opaque) { }
static int64_t clock_ns(void *opaque) { return 0; }
static SlirpCb callbacks = {
    .send_packet = send_packet,
    .clock_get_ns = clock_ns,
    .register_poll_socket = register_socket,
    .unregister_poll_socket = unregister_socket,
};

static void echo(Slirp *s, int ttl)
{
    struct mbuf *m = m_get(s);
    struct ip *ip = mtod(m, struct ip *);
    struct icmp *icmp = (struct icmp *)(ip + 1);

    memset(ip, 0, sizeof(*ip) + ICMP_MINLEN);
    ip->ip_v = IPVERSION;
    ip->ip_hl = sizeof(*ip) / 4;
    ip->ip_len = ICMP_MINLEN;
    ip->ip_ttl = ttl;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_src.s_addr = htonl(0x0a00020f);
    ip->ip_dst.s_addr = htonl(0x7f000001);
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_id = htons(1234);
    icmp->icmp_seq = htons(7);
    m->m_len = ICMP_MINLEN;
    m->m_data += sizeof(*ip);
    icmp->icmp_cksum = cksum(m, ICMP_MINLEN);
    m->m_data -= sizeof(*ip);
    m->m_len += sizeof(*ip);
    icmp_input(m, sizeof(*ip));
}

int main(void)
{
    SlirpConfig cfg = {
        .version = SLIRP_CONFIG_VERSION_MAX,
        .in_enabled = true,
        .vnetwork.s_addr = htonl(0x0a000200),
        .vnetmask.s_addr = htonl(0xffffff00),
        .vhost.s_addr = htonl(0x0a000202),
    };
    const uint8_t mac[ETH_ALEN] = { 0x52, 0x54, 0, 0, 0, 1 };
    Slirp *s = slirp_new(&cfg, &callbacks, NULL);
    arp_table_add(s, htonl(0x0a00020f), mac);
    echo(s, 1);
    g_assert_cmpuint(packets, ==, 1);
    g_assert_cmpuint(reply_len, >=, ETH_HLEN + sizeof(struct ip) + ICMP_MINLEN);
    g_assert_cmpuint(reply[ETH_HLEN + sizeof(struct ip)], ==, ICMP_TIMXCEED);
    g_assert_true(s->icmp.so_next == &s->icmp);
#ifdef __linux__
    /* No raw socket privilege is needed when Linux ping sockets are enabled. */
    echo(s, 2);
    if (s->icmp.so_next != &s->icmp) {
        struct socket *so = s->icmp.so_next;
        struct pollfd fd = { .fd = so->s, .events = POLLIN };
        int ttl;
        socklen_t len = sizeof(ttl);
        g_assert_cmpint(so->so_type, ==, IPPROTO_ICMP);
        g_assert_cmpint(getsockopt(so->s, IPPROTO_IP, IP_TTL, &ttl, &len), ==, 0);
        g_assert_cmpint(ttl, ==, 1);
        g_assert_cmpint(poll(&fd, 1, 2000), ==, 1);
        icmp_receive(so);
        g_assert_cmpuint(packets, ==, 2);
        g_assert_cmpuint(reply[ETH_HLEN + sizeof(struct ip)], ==, ICMP_ECHOREPLY);
        g_assert_cmpuint(reply[ETH_HLEN + 8], >, 0);
        g_assert_cmpuint(reply[ETH_HLEN + 8], <, MAXTTL);
        g_print("Verified Linux SOCK_DGRAM ICMP, outgoing TTL 1, reply TTL %u\n",
                reply[ETH_HLEN + 8]);
    } else {
        g_test_message("Host does not permit ICMP ping sockets; loopback check skipped");
    }
#endif
    slirp_cleanup(s);
    return 0;
}
