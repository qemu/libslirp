/* SPDX-License-Identifier: BSD-3-Clause */
#include "slirp.h"

static SlirpCb callbacks;

int main(void)
{
    struct in_addr addr = { .s_addr = htonl(0x01010101) };
    struct in6_addr addr6 = IN6ADDR_LOOPBACK_INIT;
    const char *valid[] = { "example.org", "example.net", NULL };
    const char *invalid[] = { "bad..domain", NULL };
    SlirpConfig cfg = {
        .version = SLIRP_CONFIG_VERSION_MAX,
        .advertised_nameservers = &addr,
        .advertised_nameservers_len = 1,
        .advertised_nameservers6 = &addr6,
        .advertised_nameservers6_len = 1,
    };
    Slirp *s = slirp_new(&cfg, &callbacks, NULL);
    uint8_t *search;
    size_t search_len;

    g_assert_nonnull(s);
    g_assert_true(s->advertised_nameservers != &addr);
    g_assert_true(s->advertised_nameservers6 != &addr6);
    g_assert_cmpmem(s->advertised_nameservers, sizeof(addr), &addr, sizeof(addr));
    g_assert_cmpmem(s->advertised_nameservers6, sizeof(addr6), &addr6, sizeof(addr6));
    g_assert_cmpint(slirp_set_advertised_nameservers(s, 1, NULL), ==, -1);
    g_assert_cmpuint(s->advertised_nameservers_len, ==, 1);
    g_assert_cmpint(slirp_set_advertised_nameservers(s, 1, s->advertised_nameservers), ==, 0);
    g_assert_cmpint(slirp_set_advertised_nameservers6(s, 1, s->advertised_nameservers6), ==, 0);
    slirp_set_vdomainname(s, "example.org");
    slirp_set_vdomainname(s, slirp_get_vdomainname(s));
    g_assert_cmpstr(slirp_get_vdomainname(s), ==, "example.org");
    g_assert_cmpint(slirp_set_vdnssearch(s, valid), ==, 0);
    search = s->vdnssearch;
    search_len = s->vdnssearch_len;
    g_assert_cmpint(slirp_set_vdnssearch(s, invalid), <, 0);
    g_assert_true(search == s->vdnssearch);
    g_assert_cmpuint(s->vdnssearch_len, ==, search_len);
    g_assert_cmpint(slirp_set_vdnssearch(s, valid), ==, 0);
    g_assert_cmpint(slirp_set_vdnssearch(s, NULL), ==, 0);
    g_assert_null(s->vdnssearch);
    g_assert_cmpuint(s->vdnssearch_len, ==, 0);
    g_assert_cmpint(slirp_set_advertised_nameservers(s, 0, NULL), ==, 0);
    g_assert_cmpint(slirp_set_advertised_nameservers6(s, 0, NULL), ==, 0);
    g_assert_null(s->advertised_nameservers);
    g_assert_null(s->advertised_nameservers6);
    slirp_set_vnameserver(s, addr);
    slirp_set_vnameserver6(s, addr6);
    slirp_set_disable_dns(s, true);
    g_assert_cmpmem(&s->vnameserver_addr, sizeof(addr), &addr, sizeof(addr));
    g_assert_cmpmem(&s->vnameserver_addr6, sizeof(addr6), &addr6, sizeof(addr6));
    g_assert_true(s->disable_dns);
    g_assert_cmpuint(slirp_get_vnetwork(s).s_addr, ==, cfg.vnetwork.s_addr);
    slirp_cleanup(s);
    cfg.version = 6;
    s = slirp_new(&cfg, &callbacks, NULL);
    g_assert_cmpuint(s->advertised_nameservers_len, ==, 0);
    g_assert_cmpuint(s->advertised_nameservers6_len, ==, 0);
    slirp_cleanup(s);
    return 0;
}
