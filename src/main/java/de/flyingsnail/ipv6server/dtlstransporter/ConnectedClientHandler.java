/*
 * Copyright (c) 2020 Dr. Andreas Feldner.
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License along
 *      with this program; if not, write to the Free Software Foundation, Inc.,
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *   Contact information and current version at http://www.flying-snail.de/IPv6Droid
 *
 *
 */

package de.flyingsnail.ipv6server.dtlstransporter;

import org.bouncycastle.tls.DTLSTransport;

import java.net.InetSocketAddress;

/**
 * This callback interface must be implemented in order to handle a DTLS based protocol with a single
 * client. The callback will be triggered on successful client validation and TLS parameter negotiation.
 */
interface ConnectedClientHandler {
    /**
     * Handle a new authenticated client with valid DTLS session. Note that each call tends to be
     * done in a new thread and it is OK to let handle run as long as the DTLS session can be kept
     * alive.
     * @param server a IPv6DTlsServer handling the DTLS endpoint for the specific authenticated client
     * @param dtlsTransport the DTLSTransport representing the valid DTLS session.
     * @param client the InetSocketAddress identifying the connected client.
     */
    void handle(IPv6DTlsServer server, DTLSTransport dtlsTransport, InetSocketAddress client);
}
