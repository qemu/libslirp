/* SPDX-License-Identifier: BSD-3-Clause */
#include "slirp.h"

static SlirpCb callbacks;

static void check_pool(Slirp *s, int expected)
{
    struct mbuf *m = m_get(s);
    g_assert_cmpint(M_ROOM(m), >=, expected);
    memset(m->m_data, 0xa5, expected);
    m_free(m);
    m = m_get(s);
    g_assert_cmpint(M_ROOM(m), >=, expected);
    memset(m->m_data, 0x5a, expected);
    m_free(m);
}

int main(void)
{
    SlirpConfig cfg = {
        .version = SLIRP_CONFIG_VERSION_MAX,
        .if_mtu = 9000,
        .if_mru = 8000,
    };
    Slirp *s = slirp_new(&cfg, &callbacks, NULL);
    g_assert_cmpint(s->if_mtu6, ==, 9000);
    g_assert_cmpint(s->if_mru6, ==, 8000);
    check_pool(s, 9000);
    slirp_cleanup(s);
    cfg.if_mtu = 1500;
    cfg.if_mtu6 = 9000;
    cfg.if_mru6 = 4000;
    s = slirp_new(&cfg, &callbacks, NULL);
    g_assert_cmpint(s->if_mtu6, ==, 9000);
    g_assert_cmpint(s->if_mru6, ==, 4000);
    check_pool(s, 9000);
    slirp_cleanup(s);
    cfg.version = 6;
    s = slirp_new(&cfg, &callbacks, NULL);
    g_assert_cmpint(s->if_mtu6, ==, 1500);
    g_assert_cmpint(s->if_mru6, ==, 8000);
    check_pool(s, 1500);
    slirp_cleanup(s);
    return 0;
}
