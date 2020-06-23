// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef __WIFIBROADCAST_HPP__
#define __WIFIBROADCAST_HPP__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sodium.h>
#include <endian.h>

#define MAX_PACKET_SIZE 1510
#define MAX_RX_INTERFACES 8

using namespace std;

extern string string_format(const char *format, ...);

/*
 Wifibroadcast protocol:

     wblock_hdr_t   { packet_type, nonce = (block_idx << 8 + fragment_idx) }
       wpacket_hdr_t  { packet_size }  #
         data                          #
                                       +-- encrypted

 */

// nonce:  56bit block_idx + 8bit fragment_idx

#define BLOCK_IDX_MASK ((1LLU << 56) - 1)
#define MAX_BLOCK_IDX ((1LLU << 55) - 1)


#define WFB_PACKET_DATA 0x1
#define WFB_PACKET_KEY 0x2

#define SESSION_KEY_ANNOUNCE_MSEC 1000

// Network packet headers. All numbers are in network (big endian) format
// Encrypted packets can be either session key or data packet.

// Session key packet

typedef struct {
    uint8_t packet_type;
    uint8_t session_key_nonce[crypto_box_NONCEBYTES];  // random data
    uint8_t session_key_data[crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES]; // encrypted session key
} __attribute__ ((packed)) wsession_key_t;

// Data packet. Embed FEC-encoded data

typedef struct {
    uint8_t packet_type;
    uint64_t nonce;  // big endian, nonce = block_idx << 8 + fragment_idx
}  __attribute__ ((packed)) wblock_hdr_t;

// Plain data packet after FEC decode

typedef struct {
    uint16_t packet_size; // big endian
}  __attribute__ ((packed)) wpacket_hdr_t;

#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES - sizeof(wpacket_hdr_t))
#define MAX_FEC_PAYLOAD  (MAX_PACKET_SIZE - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES)
#define MAX_FORWARDER_PACKET_SIZE (MAX_PACKET_SIZE)

int open_udp_socket_for_rx(int port);
uint64_t get_time_ms(void);

#endif
