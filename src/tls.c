/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * This is a minimal TLS implementation intended only to parse the server name
 * extension.  This was created based primarily on Wireshark dissection of a
 * TLS handshake and RFC4366.
 */
#include <stdio.h>
#include <stdlib.h> /* malloc() */
#include <string.h> /* strncpy() */
#include <sys/socket.h>
#include "tls.h"
#include "protocol.h"
#include "logger.h"

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif


struct TLSProtocol {
    int prefer_alpn;
    size_t alpn_protocol_count;
    char alpn_protocols[];
};


static int parse_tls_header(struct TLSProtocol *, const char *, size_t, char **);
static int parse_extensions(const struct TLSProtocol *, const char *, size_t, char **);
static int parse_server_name_extension(const char *, size_t, char **);
static int parse_alpn_extension(const struct TLSProtocol *, const char *, size_t , char **);
static size_t tls_data_size(const struct TLSProtocol *);
static int is_alpn_proto_known(const struct TLSProtocol *, const char *, unsigned);


static const char tls_alert[] = {
    0x15, /* TLS Alert */
    0x03, 0x01, /* TLS version  */
    0x00, 0x02, /* Payload length */
    0x02, 0x28, /* Fatal, handshake failure */
};

static const struct Protocol tls_protocol_st = {
    .name = "tls",
    .default_port = 443,
    .parse_packet = (int (*)(void *, const char *, size_t, char **))&parse_tls_header,
    .abort_message = tls_alert,
    .abort_message_len = sizeof(tls_alert)
};
const struct Protocol *tls_protocol = &tls_protocol_st;


/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
static int
parse_tls_header(struct TLSProtocol *tls_data, const char *data, size_t data_len, char **hostname) {
    char tls_content_type;
    char tls_version_major;
    char tls_version_minor;
    size_t pos = TLS_HEADER_LEN;
    size_t len;

    if (hostname == NULL)
        return -3;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return -1;

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        debug("Request did not begin with TLS handshake.");
        return -5;
    }

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3) {
        debug("Received SSL %d.%d handshake which cannot be parsed.",
              tls_version_major, tls_version_minor);

        return -2;
    }

    /* TLS record length */
    len = ((unsigned char)data[3] << 8) +
        (unsigned char)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;

    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return -5;
    }
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        debug("Not a client hello");

        return -5;
    }

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > data_len)
        return -5;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return -5;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return -5;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        debug("Received SSL 3.0 handshake without extensions");
        return -2;
    }

    /* Extensions */
    if (pos + 2 > data_len)
        return -5;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return -5;
    return parse_extensions(tls_data, data + pos, len, hostname);
}

static int
parse_extensions(const struct TLSProtocol *tls_data, const char *data, size_t data_len, char **hostname) {
    size_t pos = 0;
    size_t len;
    char *sni_name = NULL;
    int sni_len = -2;
    char *alpn_name = NULL;
    int alpn_len = -2;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 < data_len) {
        /* Extension Length */
        len = ((unsigned char)data[pos + 2] << 8) +
            (unsigned char)data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) { /* Server Name */
            /* There can be only one extension of each type, so we break
               our state and move pos to beginning of the extension here */
            if (pos + 4 + len > data_len)
                return -5;
            sni_len = parse_server_name_extension(data + pos + 4, len, &sni_name);
        } else if (data[pos] == 0x00 && data[pos + 1] == 0x10) { /* ALPN */
            if (pos + 4 + len > data_len)
                return -5;
            alpn_len = parse_alpn_extension(tls_data, data + pos + 4, len, &alpn_name);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    if (alpn_len >= 0 && (tls_data->prefer_alpn || sni_len < 0)) {
        free(sni_name);
        *hostname = alpn_name;
        return alpn_len;
    } else if (sni_len >= 0) {
        free(alpn_name);
        *hostname = sni_name;
        return sni_len;
    }

    return -2;
}

static int
parse_server_name_extension(const char *data, size_t data_len,
        char **hostname) {
    size_t pos = 2; /* skip server name list length */
    size_t len;
    char *result = NULL;

    while (pos + 3 < data_len) {
        len = ((unsigned char)data[pos + 1] << 8) +
            (unsigned char)data[pos + 2];

        if (pos + 3 + len > data_len)
            return -5;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                result = malloc(len + 1);
                if (result == NULL) {
                    err("malloc() failure");
                    return -4;
                }

                strncpy(result, data + pos + 3, len);

                result[len] = '\0';

                *hostname = result;
                return len;
            default:
                debug("Unknown server name extension name type: %d",
                      data[pos]);
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int
parse_alpn_extension(const struct TLSProtocol *tls_data, const char *data, size_t data_len, char **hostname) {
    size_t pos = 2;
    size_t len;
    char *result = NULL;

    while (pos + 1 < data_len) {
        len = (unsigned char)data[pos];

        if (pos + 1 + len > data_len)
            return -5;

        if (len > 0 && is_alpn_proto_known(tls_data, data + pos + 1, len)) {
            result = malloc(len + 1);
            if (result == NULL) {
                err("malloc() failure");
                return -4;
            }

            memcpy(result, data + pos + 1, len);
            result[len] = '\0';

            *hostname = result;
            return len;
        } else if (len > 0) {
            debug("Unknown ALPN name: %.*s", (int)len, data + pos + 2);
        }
        pos += 1 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static size_t
tls_data_size(const struct TLSProtocol *tls_data) {
    size_t size = 0;


    for (size_t i = 0; i < tls_data->alpn_protocol_count; i++) {
        int alpn_protocol_len = (unsigned char)tls_data->alpn_protocols[size++];
        size += alpn_protocol_len;
    }

    return sizeof(struct TLSProtocol) + size;
}

struct TLSProtocol *
new_tls_data() {
    struct TLSProtocol *tls_data = malloc(sizeof(struct TLSProtocol));
    if (tls_data != NULL) {
        tls_data->prefer_alpn = 0;
        tls_data->alpn_protocol_count = 0;
    }

    return tls_data;
}

struct TLSProtocol *
tls_data_append_alpn_protocol(struct TLSProtocol *old_tls_data, const char *name, size_t name_len) { if (name_len > 255) {
        err("%s: name too long: %ld bytes", __func__, name_len);
        return old_tls_data;
    }
    size_t old_size = tls_data_size(old_tls_data);
    size_t new_size = old_size + name_len + 1;

    struct TLSProtocol *new_tls_data = realloc(old_tls_data, new_size);
    if (new_tls_data == NULL) {
        err("%s: malloc", __func__);
        return old_tls_data;
    }

    size_t pos = 0;
    for (size_t i = 0; i < new_tls_data->alpn_protocol_count; i++) {
        int alpn_protocol_len = (unsigned char)new_tls_data->alpn_protocols[pos];
        pos += alpn_protocol_len + 1;
    }

    new_tls_data->alpn_protocols[pos++] = name_len;
    memcpy(new_tls_data->alpn_protocols + pos, name, name_len);
    new_tls_data->alpn_protocol_count++;

    return new_tls_data;
}

struct TLSProtocol *
tls_data_prefer_alpn(struct TLSProtocol *tls_data, int prefer_alpn) {
    tls_data->prefer_alpn = prefer_alpn;

    return tls_data;
}

static int
is_alpn_proto_known(const struct TLSProtocol *tls_data, const char* name, unsigned name_len) {
    size_t pos = 0;
    for (size_t i = 0; i < tls_data->alpn_protocol_count; i++) {
        int alpn_protocol_len = (unsigned char)tls_data->alpn_protocols[pos++];
        if (name_len == alpn_protocol_len
                && strncmp(tls_data->alpn_protocols + pos, name, name_len))
            return 1;

        pos += alpn_protocol_len;
    }
    return 0;
}
