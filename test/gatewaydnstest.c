/* SPDX-License-Identifier: BSD-3-Clause */
#include "slirp.h"

static SlirpCb callbacks;

int main(void)
{
    SlirpConfig cfg = {
        .version = SLIRP_CONFIG_VERSION_MAX,
        .vnetwork.s_addr = htonl(0x0a000200),
        .vnetmask.s_addr = htonl(0xffffff00),
        .vhost.s_addr = htonl(0x0a000202),
        .vnameserver.s_addr = htonl(0x0a000203),
        .disable_host_loopback = true,
    };
    Slirp *s;
    struct socket so = { 0 };
    struct sockaddr_storage storage = { .ss_family = AF_INET };
    struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&storage;
    cfg.vhost6.s6_addr[0] = 0xfd;
    cfg.vhost6.s6_addr[15] = 2;
    s = slirp_new(&cfg, &callbacks, NULL);
    so.slirp = s;
    so.so_faddr = cfg.vhost;
    so.so_fport = htons(53);
    addr->sin_addr.s_addr = htonl(0x08080808);
    addr->sin_port = htons(5353);
    sotranslate_in(&so, &storage);
    g_assert_cmphex(addr->sin_addr.s_addr, ==, cfg.vhost.s_addr);
    g_assert_cmpuint(addr->sin_port, ==, htons(53));
    so.so_fport = htons(54);
    g_assert_cmpint(sotranslate_out(&so, &storage), ==, -1);
    s->disable_dns = true;
    so.so_fport = htons(53);
    g_assert_cmpint(sotranslate_out(&so, &storage), ==, -1);
    s->disable_dns = false;
    memset(&storage, 0, sizeof(storage));
    storage.ss_family = AF_INET6;
    so.so_faddr6 = cfg.vhost6;
    so.so_fport = htons(53);
    addr6->sin6_addr = in6addr_loopback;
    addr6->sin6_port = htons(5353);
    sotranslate_in(&so, &storage);
    g_assert_true(in6_equal(&addr6->sin6_addr, &cfg.vhost6));
    g_assert_cmpuint(addr6->sin6_port, ==, htons(53));
    slirp_cleanup(s);
    return 0;
}
