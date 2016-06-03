/**
 * Copyright (c) 2016 Dr. Andreas Feldner.
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Contact information and current version at http://www.flying-snail.de/IPv6Droid
 */
package de.flyingsnail.ipv6backwardserver.transporter;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.rmi.NoSuchObjectException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.jdt.annotation.NonNull;

import de.flyingsnail.ipv6backwarddata.ayiya.AyiyaServer;
import de.flyingsnail.ipv6backwarddata.ayiya.BufferWriter;
import de.flyingsnail.ipv6backwarddata.ayiya.ConnectionFailedException;


/**
 * A runnable that handles incoming AYIYA packets over IPv4.
 * 
 * @author pelzi
 *
 */
public class IPv4InputHandler implements Runnable {
  private @NonNull AyiyaData ayiyaData;
  private @NonNull DatagramChannel ipv4Channel;
  private Logger logger = Logger.getLogger(getClass().getName());
  private @NonNull BufferWriter ipv6out;

  public IPv4InputHandler(@NonNull AyiyaData ayiyaData, @NonNull DatagramChannel ipv4Channel, @NonNull BufferWriter ipv6out) {
    this.ayiyaData = ayiyaData;
    this.ipv4Channel = ipv4Channel;
    this.ipv6out = ipv6out;
  }

  /* (non-Javadoc)
   * @see java.lang.Runnable#run()
   */
  @Override
  public void run() {
    logger.info("Listening for udp packets");
    ByteBuffer buffer = ByteBuffer.allocate(1500);
    while (ipv4Channel.isOpen()) {
      try {
        buffer.clear();
        SocketAddress clientAddress = ipv4Channel.receive(buffer);
        logger.finer("Received packet, size " + buffer.position());
        buffer.limit(buffer.position());
        buffer.position(0);
        handleAyiyaPacket(buffer, clientAddress);
      } catch (Exception e) {
        logger.log(Level.WARNING, "Exception in IPv4 reader thread", e);
      }
    }
  }

  private void handleAyiyaPacket(ByteBuffer buffer, SocketAddress clientAddress) throws IllegalArgumentException, IOException, ConnectionFailedException {
    Inet6Address sender = AyiyaServer.precheckPacket(buffer.array(), buffer.arrayOffset(), buffer.limit());
    if (sender == null)
      return;
    AyiyaServer ayiyaServer;
    try {
      ayiyaServer = ayiyaData.getServer(sender);
    } catch (NoSuchObjectException e) {
      logger.log(Level.WARNING, "Unsupported IPv6 address referred from incoming IPv6 packet: {0}", sender);
      return;
    }
    if (!ayiyaServer.isConnected())
      ayiyaServer.connect(ipv6out, clientAddress);
    if (!ayiyaServer.getClientAddress().equals(clientAddress))
      ayiyaServer.reconnect(ipv6out, clientAddress);
    ayiyaServer.writeToIPv6(buffer);
  }


}
