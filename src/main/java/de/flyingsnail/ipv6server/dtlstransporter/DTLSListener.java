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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.DTLSRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DTLSVerifier;
import org.bouncycastle.tls.DatagramSender;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.UDPTransport;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class DTLSListener {
    public static final String TRUSTED_ISSUER = "C=DE,ST=Hessen,L=Bad Vilbel,O=Flying Furry CSnail Creature,OU=Private Cloud,CN=Commander Pelzi,E=ca@flying-snail.de";
    private final Logger logger = Logger.getLogger(DTLSListener.class.getName());
    private final int mtu;
    static final int MAX_MTU = 64*1024;
    private final static int OVERHEAD = 92;
    private final int heartbeat;
    private DatagramSocket socket;

    private InetSocketAddress myIpv4;

    private boolean shouldRun;

    public DTLSListener (TransporterParams params) throws IOException {
        myIpv4 = new InetSocketAddress(params.ipv4Pop, params.portPop);
        mtu = params.mtu;
        heartbeat = params.heartbeat;
        // UDP bound, unconnected socket (listener)
        socket = new DatagramSocket(null);
        socket.setSoTimeout(0); // no timeout
        socket.setReuseAddress(true);
        socket.bind(myIpv4);

        logger.info("DTLSListener constructed");
    }

    public void listen(ConnectedClientHandler connectedClientHandler) throws IOException {
        logger.info("About to listen");
        DTLSVerifier verifier = new DTLSVerifier(new BcTlsCrypto(new SecureRandom()));

        byte[] data = new byte[MAX_MTU];
        final DatagramPacket packet = new DatagramPacket(data, data.length);

        // Process incoming packets, replying with HelloVerifyRequest, spawn verified.
        shouldRun = true;
        while (shouldRun) {
            socket.receive(packet);
            if (!shouldRun) {
                break;
            }

            final InetSocketAddress clientAddress = (InetSocketAddress)packet.getSocketAddress();
            logger.fine("Received UDP packet from " + packet.getSocketAddress().toString());

            final DTLSRequest request = verifier.verifyRequest(clientAddress.getAddress().getAddress(),
                    data,
                    0,
                    packet.getLength(),
                    new DatagramSender() {
                @Override
                public int getSendLimit() throws IOException {
                    return mtu + OVERHEAD;
                }

                @Override
                public void send(byte[] buf, int off, int len) throws IOException {
                    if (len > getSendLimit()) {
                        throw new TlsFatalAlert(AlertDescription.internal_error);
                    }

                    socket.send(new DatagramPacket(buf, off, len, clientAddress));
                }
            });

            if (request != null) {
                logger.info("Accepted connection from " + clientAddress.toString());
                DatagramSocket clientSocket;
                // create new accepting socket
                final DatagramSocket newSocket = new DatagramSocket(null);
                newSocket.setSoTimeout(0);
                newSocket.setReuseAddress(true);
                newSocket.bind(myIpv4);
                newSocket.connect(clientAddress);

                clientSocket = newSocket;

                // spawn a thread to establish session
                final Thread handlerThread = new Thread(
                        () -> {

                            try {
                                connect(connectedClientHandler,
                                        clientSocket,
                                        request);
                            } catch (Throwable e) {
                                logger.log(Level.WARNING, "Failed to establish DTLS session for client " + socket.getRemoteSocketAddress(), e);
                            }
                        },
                        "DTLS acceptor for " + clientAddress);
                handlerThread.start();
            } else {
              logger.info("Not accepting connection from " + clientAddress.toString());
            }
        }

        logger.info("Accept loop ended gracefully");
    }

    private void connect(ConnectedClientHandler connectedClientHandler, DatagramSocket socket, DTLSRequest firstPacket) throws IOException {
        final DatagramTransport transport = new UDPTransport(socket, mtu + 2*OVERHEAD) {
            @Override
            public int getReceiveLimit() {
                // we do not want to limit incoming packages
                return MAX_MTU;
            }
        };

        final IPv6DTlsServer server = new IPv6DTlsServer(heartbeat);

        DTLSServerProtocol protocol = new DTLSServerProtocol();

        final DTLSTransport dtls = protocol.accept(server, transport, firstPacket);
        
        logger.info( "DTLS session for client " + socket.getRemoteSocketAddress() + " created.");

        try {
            connectedClientHandler.handle(server, dtls, (InetSocketAddress) socket.getRemoteSocketAddress());
        } finally {
            dtls.close();
        }
        logger.info ("DTLS session for client " + socket.getRemoteSocketAddress() + " terminated.");
    }


    public void close() {
        logger.info("Closing DTLSListener");
        shouldRun = false;
        socket.close();
    }

}
