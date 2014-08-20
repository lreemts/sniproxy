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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include "addressmap.h"
#include "logger.h"

struct AddressmapEntry {
    uint8_t address[16];
    uint16_t port;
};

static struct AddressmapEntry* addressmap = NULL;

static uint8_t ipv4_to_ipv6_prefix = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };

#define ADDRESSMAP_SIZE (sizeof( struct AddressmapEntry ) * (1<<16))

void init_addressmap(struct Config *config)
{
    if( config->addressmap_shm )
    {
        key_t key;
        int shmid;
        void* shmaddr;

        key = ftok(config->addressmap_shm, 'M');
        
        if( key < 0 )
        {
            err( "Error getting addressmap key for file %s: %s", config->addressmap_shm, strerror() );
            return;
        }
        shmid = shmget(key, ADDRESSMAP_SIZE, 0644 | IPC_CREAT);
        if( shmid < 0 )
        {
            err( "Error getting shm id for file %s: %s", config->addressmap_shm, strerror() );
            return;
        }
        
        shmaddr = shmat( shmid, NULL, 0 );
        
        if( shmaddr == ((void *) -1)
        {
            err( "Error mapping shared memory for file %s: %s", config->addressmap_shm, strerror() );
            return;
        }
        
        addressmap = (struct AddressmapEntry*) shmaddr;
    }
}

void update_addressmap(struct Connection *con, int local_fw_socket)
{
    struct sockaddr_storage local_address;
    socklen_t local_address_len = sizeof(local_address);

    if( getsockname( local_fw_socket, &local_address, &local_address_len ) < 0 )
    {
        warn( "Getting local address for forwarded connection: %s", strerror( errno ) );
        return;
    }

    AddressmapEntry* entry = NULL;
    
    switch (((struct sockaddr *)local_address)->sa_family) {
        case AF_INET:
            if( memcmp( ((struct sockaddr_in *)local_address)->sin_addr, ipv4_loopback, 4 ) == 0 )
            {
                entry = &addressmap[((struct sockaddr_in *)local_address)->sin_port];
            }
            break;
        case AF_INET6:
            if( memcmp( ((struct sockaddr_in6 *)local_address)->sin6_addr, ipv6_loopback, 16 ) == 0 )
            {
                entry = &addressmap[((struct sockaddr_in6 *)local_address)->sin6_port];
            }
            break;
    }
    
    if( entry )
    {
        const struct sockaddr * client_address = (const struct sockaddr *) con->client.addr;
    
        switch (client_address->sa_family) {
            case AF_INET:
                memcpy( entry->address, ipv4_to_ipv6_prefix, 10 );
                memcpy( entry->address + 10, ((struct sockaddr_in *)client_address)->sin_addr, 4 );
                entry->port = ((struct sockaddr_in *)client_address)->sin_port;
                break;
            case AF_INET6:
                memcpy( entry->address, ((struct sockaddr_in6 *)client_address)->sin6_addr, sizeof(entry->address) );
                entry->port = ((struct sockaddr_in *)client_address)->sin6_port;
                break;
        }
    }
}
