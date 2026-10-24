/* SPDX-License-Identifier: BSD-3-Clause */
/* tftp defines */

#ifndef SLIRP_TFTP_H
#define SLIRP_TFTP_H

#include "util.h"

#define TFTP_SESSIONS_MAX 20

#define TFTP_SERVER 69

#define TFTP_RRQ 1
#define TFTP_WRQ 2
#define TFTP_DATA 3
#define TFTP_ACK 4
#define TFTP_ERROR 5
#define TFTP_OACK 6

#define TFTP_FILENAME_MAX 512

SLIRP_PACKED_BEGIN
struct tftphdr {
    struct udphdr udp;
    uint16_t tp_op;
} SLIRP_PACKED_END;

SLIRP_PACKED_BEGIN
struct tftp_t {
    struct tftphdr hdr;
    union {
        struct {
            uint16_t tp_block_nr;
            uint8_t tp_buf[0];
        } tp_data;
        struct {
            uint16_t tp_error_code;
            uint8_t tp_msg[0];
        } tp_error;
        char tp_buf[0];
    } x;
} SLIRP_PACKED_END;

struct tftp_session {
    Slirp *slirp;
    char *filename;
    int fd;
    uint16_t block_size;

    struct sockaddr_storage client_addr;
    uint16_t client_port;
    uint32_t block_nr;

    int timestamp;
};

/* Process TFTP packet coming from the guest */
void tftp_input(struct sockaddr_storage *srcsas, struct mbuf *m);

/* Clear remaining sessions */
void tftp_cleanup(Slirp *slirp);

#endif
