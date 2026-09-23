/* SPDX-License-Identifier: BSD-3-Clause */
#include "slirp.h"

static SlirpCb callbacks;

int main(void)
{
    SlirpConfig cfg = {
        .version = SLIRP_CONFIG_VERSION_MAX,
        .vnetwork.s_addr = htonl(0x0a000000),
        .vnetmask.s_addr = htonl(0xffff0000),
        .vhost.s_addr = htonl(0x0a000002),
        .forward_broadcast = true,
        .hostfwd_listen_backlog = 32,
        .disable_host_loopback = true,
    };
    Slirp *s = slirp_new(&cfg, &callbacks, NULL);
    struct socket so = { .slirp = s };
    struct sockaddr_in addr = { .sin_family = AF_INET };

    g_assert_cmpint(s->hostfwd_listen_backlog, ==, 32);
    so.so_faddr.s_addr = htonl(0x0a00ffff);
    so.so_ffamily = AF_INET;
    g_assert_cmpint(sotranslate_out(&so, (struct sockaddr_storage *)&addr), ==, 0);
    g_assert_cmphex(addr.sin_addr.s_addr, ==, INADDR_BROADCAST);
    so.so_faddr.s_addr = INADDR_BROADCAST;
    g_assert_cmpint(sotranslate_out(&so, (struct sockaddr_storage *)&addr), ==, 0);
    so.so_faddr = cfg.vhost;
    g_assert_cmpint(sotranslate_out(&so, (struct sockaddr_storage *)&addr), ==, -1);
    slirp_cleanup(s);
    cfg.version = 6;
    s = slirp_new(&cfg, &callbacks, NULL);
    g_assert_false(s->forward_broadcast);
    g_assert_cmpint(s->hostfwd_listen_backlog, ==, 1);
    so.slirp = s;
    so.so_faddr.s_addr = INADDR_BROADCAST;
    g_assert_cmpint(sotranslate_out(&so, (struct sockaddr_storage *)&addr), ==, -1);
    slirp_cleanup(s);
    return 0;
}
