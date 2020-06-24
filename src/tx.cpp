// -*- C++ -*-
//
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/resource.h>
#include <assert.h>

#include <string>
#include <memory>
#include <vector>

extern "C"
{
#include "fec.h"
}

#include "wifibroadcast.hpp"
#include "tx.hpp"

Transmitter::Transmitter(int k, int n, const string &keypair):  fec_k(k), fec_n(n), block_idx(0),
                                                                fragment_idx(0),
                                                                max_packet_size(0)
{
    fec_p = fec_new(fec_k, fec_n);

    block = new uint8_t*[fec_n];
    for(int i=0; i < fec_n; i++)
    {
        block[i] = new uint8_t[MAX_FEC_PAYLOAD];
    }

    FILE *fp;
    if((fp = fopen(keypair.c_str(), "r")) == NULL)
    {
        throw runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
    }
    if (fread(tx_secretkey, crypto_box_SECRETKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read tx secret key: %s", strerror(errno)));
    }
    if (fread(rx_publickey, crypto_box_PUBLICKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read rx public key: %s", strerror(errno)));
    }
    fclose(fp);

    make_session_key();
}

Transmitter::~Transmitter()
{
    for(int i=0; i < fec_n; i++)
    {
        delete block[i];
    }
    delete block;

    fec_free(fec_p);
}


void Transmitter::make_session_key(void)
{
    randombytes_buf(session_key, sizeof(session_key));
    session_key_packet.packet_type = WFB_PACKET_KEY;
    randombytes_buf(session_key_packet.session_key_nonce, sizeof(session_key_packet.session_key_nonce));
    if (crypto_box_easy(session_key_packet.session_key_data, session_key, sizeof(session_key),
                        session_key_packet.session_key_nonce, rx_publickey, tx_secretkey) != 0)
    {
        throw runtime_error("Unable to make session key!");
    }
}

void Transmitter::send_block_fragment(size_t packet_size)
{
    uint8_t ciphertext[MAX_FORWARDER_PACKET_SIZE];
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)ciphertext;
    long long unsigned int ciphertext_len;

    assert(packet_size <= MAX_FEC_PAYLOAD);

    block_hdr->packet_type = WFB_PACKET_DATA;
    block_hdr->nonce = htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);

    // encrypted payload
    crypto_aead_chacha20poly1305_encrypt(ciphertext + sizeof(wblock_hdr_t), &ciphertext_len,
                                         block[fragment_idx], packet_size,
                                         (uint8_t*)block_hdr, sizeof(wblock_hdr_t),
                                         NULL, (uint8_t*)(&(block_hdr->nonce)), session_key);

    inject_packet(ciphertext, sizeof(wblock_hdr_t) + ciphertext_len);
}

void Transmitter::send_session_key(void)
{
    //fprintf(stderr, "Announce session key\n");
    inject_packet((uint8_t*)&session_key_packet, sizeof(session_key_packet));
}

void Transmitter::send_packet(const uint8_t *buf, size_t size)
{
    wpacket_hdr_t packet_hdr;
    assert(size <= MAX_PAYLOAD_SIZE);

    packet_hdr.packet_size = htobe16(size);
    memset(block[fragment_idx], '\0', MAX_FEC_PAYLOAD);
    memcpy(block[fragment_idx], &packet_hdr, sizeof(packet_hdr));
    memcpy(block[fragment_idx] + sizeof(packet_hdr), buf, size);
    send_block_fragment(sizeof(packet_hdr) + size);
    max_packet_size = max(max_packet_size, sizeof(packet_hdr) + size);
    fragment_idx += 1;

    if (fragment_idx < fec_k)  return;

    fec_encode(fec_p, (const uint8_t**)block, block + fec_k, max_packet_size);
    while (fragment_idx < fec_n)
    {
        send_block_fragment(max_packet_size);
        fragment_idx += 1;
    }
    block_idx += 1;
    fragment_idx = 0;
    max_packet_size = 0;

    // Generate new session key after MAX_BLOCK_IDX blocks
    if (block_idx > MAX_BLOCK_IDX)
    {
        make_session_key();
        send_session_key();
        block_idx = 0;
    }
}

void video_source(shared_ptr<Transmitter> &t, vector<int> &tx_fd)
{
    int nfds = tx_fd.size();
    struct pollfd fds[nfds];
    memset(fds, '\0', sizeof(fds));

    int i = 0;
    for(auto it=tx_fd.begin(); it != tx_fd.end(); it++, i++)
    {
        int fd = *it;
        if(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0)
        {
            throw runtime_error(string_format("Unable to set socket into nonblocked mode: %s", strerror(errno)));
        }

        fds[i].fd = fd;
        fds[i].events = POLLIN;
    }

    uint64_t session_key_announce_ts = 0;

    for(;;)
    {
        int rc = poll(fds, nfds, -1);

        if (rc < 0){
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        if (rc == 0) continue;  // timeout expired

        for(i = 0; i < nfds; i++)
        {
            // some events detected
            if (fds[i].revents & (POLLERR | POLLNVAL))
            {
                throw runtime_error(string_format("socket error: %s", strerror(errno)));
            }

            if (fds[i].revents & POLLIN)
            {
                uint8_t buf[MAX_PAYLOAD_SIZE];
                ssize_t rsize;
                int fd = tx_fd[i];

                t->select_output(i);
                while((rsize = recv(fd, buf, sizeof(buf), 0)) >= 0)
                {
                    uint64_t cur_ts = get_time_ms();
                    if (cur_ts >= session_key_announce_ts)
                    {
                        // Announce session key
                        t->send_session_key();
                        session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_MSEC;
                    }
                    t->send_packet(buf, rsize);
                }
                if(errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
            }
        }
    }
}


int main(int argc, char * const *argv)
{
    int opt;
    uint8_t k=8, n=12;
    int udp_port=5600;

    string keypair = "drone.key";

    while ((opt = getopt(argc, argv, "K:k:n:u:")) != -1) {
        switch (opt) {
        case 'K':
            keypair = optarg;
            break;
        case 'k':
            k = atoi(optarg);
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'u':
            udp_port = atoi(optarg);
            break;
        default: /* '?' */
        show_usage:
            fprintf(stderr, "Usage: %s [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] interface1 [interface2] ...\n",
                    argv[0]);
            fprintf(stderr, "Default: K='%s', k=%d, n=%d, udp_port=%d\n",
                    keypair.c_str(), k, n, udp_port);
            fprintf(stderr, "Radio MTU: %lu\n", (unsigned long)MAX_PAYLOAD_SIZE);
            fprintf(stderr, "WFB version " WFB_VERSION "\n");
            exit(1);
        }
    }

    if (optind >= argc) {
        goto show_usage;
    }

    try
    {
        vector<int> tx_fd;
        vector<string> wlans;
        int i;
        for(i = 0; optind + i < argc; i++)
        {
            int fd = open_udp_socket_for_rx(udp_port + i);
            fprintf(stderr, "Listen on %d\n", udp_port + i);
            tx_fd.push_back(fd);
            wlans.push_back(string(argv[optind + i]));
        }

        shared_ptr<Transmitter>t = shared_ptr<UdpTransmitter>(new UdpTransmitter(k, n, keypair, "127.0.0.1", udp_port + i));
        fprintf(stderr, "UDP output to %d\n", udp_port + i);

        video_source(t, tx_fd);
    }catch(runtime_error &e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
