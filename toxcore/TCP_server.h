/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of the TCP relay server part of Tox.
 */
#ifndef C_TOXCORE_TOXCORE_TCP_SERVER_H
#define C_TOXCORE_TOXCORE_TCP_SERVER_H

#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"
#include "onion.h"

#define MAX_INCOMING_CONNECTIONS 256

#define TCP_MAX_BACKLOG MAX_INCOMING_CONNECTIONS

#define ARRAY_ENTRY_SIZE 6

typedef enum TCP_Status {
    TCP_STATUS_NO_STATUS,
    TCP_STATUS_CONNECTED,
    TCP_STATUS_UNCONFIRMED,
    TCP_STATUS_CONFIRMED,
} TCP_Status;

typedef struct TCP_Server TCP_Server;

const uint8_t *_Nonnull tcp_server_public_key(const TCP_Server *_Nonnull tcp_server);
size_t tcp_server_listen_count(const TCP_Server *_Nonnull tcp_server);

/** Create new TCP server instance. */
TCP_Server *_Nullable new_tcp_server(const Logger *_Nonnull logger, const Memory *_Nonnull mem, const Random *_Nonnull rng, const Network *_Nonnull ns,
                                     bool ipv6_enabled, uint16_t num_sockets, const uint16_t *_Nonnull ports,
                                     const uint8_t *_Nonnull secret_key, Onion *_Nullable onion, Forwarding *_Nullable forwarding);
/** Run the TCP_server */
void do_tcp_server(TCP_Server *_Nonnull tcp_server, const Mono_Time *_Nonnull mono_time);

/** Kill the TCP server */
void kill_tcp_server(TCP_Server *_Nullable tcp_server);
/** @brief Returns a pointer to the net profile associated with `tcp_server`.
 *
 * Returns null if `tcp_server` is null.
 */
const Net_Profile *_Nullable tcp_server_get_net_profile(const TCP_Server *_Nullable tcp_server);

/** Add a public key to the TCP relay whitelist */
bool tcp_server_add_to_whitelist(TCP_Server *tcp_server, const uint8_t *public_key);

/** Remove a public key from the TCP relay whitelist */
bool tcp_server_remove_from_whitelist(TCP_Server *tcp_server, const uint8_t *public_key);

/** Set whether access control is enabled */
void tcp_server_set_access_control_enabled(TCP_Server *tcp_server, bool enabled);

/** Check if a public key is whitelisted */
bool tcp_server_is_whitelisted(const TCP_Server *tcp_server, const uint8_t *public_key);

#endif /* C_TOXCORE_TOXCORE_TCP_SERVER_H */
