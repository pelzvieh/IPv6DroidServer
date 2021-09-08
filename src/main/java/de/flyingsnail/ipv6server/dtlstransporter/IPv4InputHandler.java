/**
 * Copyright (c) 2020 Dr. Andreas Feldner.
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
package de.flyingsnail.ipv6server.dtlstransporter;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.rmi.NoSuchObjectException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.TlsTimeoutException;
import org.eclipse.jdt.annotation.NonNull;


/**
 * A runnable that listens to IPv4 incoming connections and handles all IPv6Droid clients, each in a separate Thread.
 * 
 * @author pelzi
 *
 */
public class IPv4InputHandler implements Runnable, ConnectedClientHandler {
  private @NonNull DTLSData dtlsData;
  private @NonNull DTLSListener dtlsServer;
  private Logger logger = Logger.getLogger(getClass().getName());
  private @NonNull BufferWriter ipv6out;
  private Date lastPacketReceivedTime;
  private boolean validPacketReceived;
  private int invalidPacketCounter;    

  /**
   * Constructor.
   * @param dtlsData the registry of DTLS sessions, used by the IPv6InputHandler to direct incoming IPv6 traffic to the correct
   *                 DTLS session.
   * @param dtlsServer the DTLS equivalent of a ServerSocket, accepting new connections
   * @param ipv6out the BufferWriter to write IPv6 packets to
   */
  public IPv4InputHandler(@NonNull DTLSData dtlsData, @NonNull DTLSListener dtlsServer, @NonNull BufferWriter ipv6out) {
    this.dtlsData = dtlsData;
    this.ipv6out = ipv6out;
    this.dtlsServer = dtlsServer;
  }

  /* (non-Javadoc)
   * @see java.lang.Runnable#run()
   */
  @Override
  public void run() {    
    try {
      logger.info("Startup completed, listening for UDP packets");
      dtlsServer.listen(this);
    } catch (IOException e) {
      logger.log(Level.WARNING, "Unexpected IOException terminates echoing server", e);
    }

  }

  /**
   * Write next packet from the tunnel to the IPv6 device.
   * @param clientAddress an Inet6Address giving the client's address according to its certificate. This is the only allowed source address.
   * @param bb a ByteBuffer containing a read packet (fixed IPv6 header plus payload), with current position set to 
   *        beginning of header, and limit set to end of payload.
   * @return a boolean indicating if the packet was correctly signed
   * @throws IOException in case of network problems (probably temporary in nature)
   * @throws IllegalArgumentException in case that the supplied ByteBuffer is trivially invalid. Packets failing to verify
   *    signature are not flagged by Exception, but instead by returning false and increased invalidPacketCounter.
   */
  public boolean writeToIPv6(Inet6Address clientAddress, ByteBuffer bb) throws IOException, IllegalArgumentException {
    if (ipv6out == null)
      throw new IllegalStateException("write() called on unconnected handler");

    // update timestamp of last packet received
    lastPacketReceivedTime = new Date();

    // check buffer content
    try {
      int contentLength = (int)ipv6out.verifyHeaderReturnPacketLength(bb);
      
      if (contentLength + IPv6InputHandler.IPV6PACKET_HEADER_LENGTH != bb.remaining()) {
        throw new IOException("Retrieved data do not represent a single IPv6 package");
      }
    } catch (IOException e) {
      logger.log(Level.INFO, "Received non-/not single IPv6 package", e);
      invalidPacketCounter++;
      return false;
    }
    
    // check source IP address
    byte[] rawIpAddress = new byte[16];
    System.arraycopy(bb.array(), bb.position() + IPv6InputHandler.IPV6PACKET_SOURCE_OFFSET + bb.arrayOffset(),
        rawIpAddress, 0, rawIpAddress.length);
    // TODO in java 16, replace by bb.get(bb.position() + IPv6InputHandler.IPV6PACKET_SOURCE_OFFSET, rawIpAddress);
    InetAddress sourceIp = Inet6Address.getByAddress(rawIpAddress);
    if (!clientAddress.equals(sourceIp)) {
      logger.log(Level.WARNING, "Received IPv6 package from Client {0} with source IP {1}", new Object[] {clientAddress, sourceIp});
      invalidPacketCounter++;
      return false;
    }
    validPacketReceived = true;
    ipv6out.write (bb);
    logger.finer("Written packet");
    return true;
  }

  @Override
  public void handle(IPv6DTlsServer dtlsServer, DTLSTransport dtlsTransport, InetSocketAddress client) {
    Inet6Address clientAddress = null;
    try {
      clientAddress = DTLSUtils.getIpv6AlternativeName(dtlsServer.getClientCert());
    } catch (IOException e) {
      logger.log(Level.WARNING, "Received package from authenticated client, not carrying an IPv6Address in its client cert", e);
      return;
    }
    try {
      closePreviousSession(clientAddress);

      // register the DTLSTransport event for the address. After this, traffic to this IPv6 address will be routed to the dtlsTransport
      dtlsData.putServer(clientAddress, dtlsTransport);

      ByteBuffer bb = ByteBuffer.allocate(dtlsTransport.getReceiveLimit());
      logger.info("Handling client " + client.getHostString());

      while (true) {
        bb.clear();
        int bytesRead = dtlsTransport.receive(bb.array(), bb.arrayOffset() + bb.position(), bb.limit() - bb.position(), 60 * 1000);
        if (bytesRead < 0) {
          logger.fine("dtlsTransport indicates eof");
          break;
        } else if (bytesRead == 0) {
          logger.finer(() -> "read 0 bytes within timeout " + client.getHostString());
          try {
            Thread.sleep(100L);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            break;
          }
          continue;
        }
        bb.limit(bytesRead);
        logger.finest("Writing package");
        writeToIPv6(clientAddress, bb);
      }
    } catch (TlsTimeoutException e) {
      logger.log(Level.INFO, "Client {0}/{1} had timeout", new Object[] {client.getHostString(), clientAddress});
    } catch (SocketException e) {
      logger.log(Level.INFO, e, () -> "Asynchronous close of onnection for client " + client.getHostString());
    } catch (IOException e) {
      logger.log(Level.WARNING, e, () -> "Connection lost with client " + client.getHostString());
    } finally {
      logger.log(Level.INFO, "Client {0}/{1} is gone", new Object[] {client.getHostString(), clientAddress});
      try {
        dtlsTransport.close();
      } catch (Exception e) {
        logger.log(Level.WARNING, "Could not close dtls session cleanly", e);
      }
      dtlsData.removeServer(clientAddress);
    }
  }

  /**
   * Check for an existing DTLSTransport associated with the IPv6 address. This means, our client changed its IPv4 address
   * @param testAddress
   * @throws IOException
   */
  private void closePreviousSession(Inet6Address testAddress) throws IOException {
    try {
      DTLSTransport previousSession = dtlsData.getServer(testAddress);
      if (previousSession != null) {
        previousSession.close(); // the still running handler will learn it the hard way :-)
        dtlsData.removeServer(testAddress);
      }
    } catch (NoSuchObjectException e) {
      // no previous instance, fine!
    }
  }

  /**
   * @return the lastPacketReceivedTime
   */
  public Date getLastPacketReceivedTime() {
    return lastPacketReceivedTime;
  }

  /**
   * @return the invalidPacketCounter
   */
  public int getInvalidPacketCounter() {
    return invalidPacketCounter;
  }

  /**
   * @return the validPacketReceived
   */
  public boolean isValidPacketReceived() {
    return validPacketReceived;
  }
}
