/**
 * Copyright (c) 2016 Dr. Andreas Feldner (pelzi).
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
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.rmi.NoSuchObjectException;
import java.util.concurrent.ForkJoinPool;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;

import de.flyingsnail.tun.LinuxTunChannel;


/**
 * IPv6InputHandler constantly reads IP packets from the IPv6 input sourceType. The underlying OS's routing
 * should be prepared in a way that ensures that these packets are each targeted at specific tunnel clients.
 * 
 * Currently, this uses an external helper program to bind to a linux tun device.
 *
 * @author pelzi
 *
 */
public class IPv6InputHandler implements Runnable, BufferWriter, AutoCloseable {
    
  private static final int IPV6PACKET_DESTINATION_OFFSET = 24;

  public static final int IPV6PACKET_HEADER_LENGTH = 40;

  static final int IPV6PACKET_LENGTH_OFFSET = 4;

  static final int IPV6PACKET_SOURCE_OFFSET = 8;

  /** 
   * The first 4  bits of a packet should give the IP version.
   */
  static final int IPV6PACKET_PROTOCOL_BYTE_OFFSET = 0;

  static final int IPV6PACKET_PROTOCOL_BIT_OFFSET = 4;
  
  private Logger logger = Logger.getLogger(getClass().getName());
  
  private @NonNull DTLSData dtlsData;

  private boolean passUnHandled;

  final ForkJoinPool executorPool = new ForkJoinPool(2 * java.lang.Runtime.getRuntime().availableProcessors());
 
  private ReadableByteChannel inputChannel;
  
  private WritableByteChannel outputChannel;

  private WritableByteChannel passOnChannel;

  /**
   * Constructor
   * @param dtlsData the registry of DTLS sessions per IPv6 address
   * @param tunDevice the name of the tun device to read from via TUNTOPIPE.
   * @param toAyiya a WritableByteChannel to write packets to that are not handled by this handler. May be null, switching off the feature.
   * @throws IllegalStateException in case of incorrectly deployed application, e.g. if TUNTOPIPE cannot be launched
   */
  public IPv6InputHandler(@NonNull DTLSData dtlsData, @NonNull String tunDevice, @Nullable WritableByteChannel toAyiya) throws IllegalStateException, IOException {
    this.dtlsData = dtlsData;
    this.passUnHandled = (toAyiya != null);
    passOnChannel = toAyiya;
    logger.info("Constructing process launching IPv6InputHandler");
    
    LinuxTunChannel netDevice = new LinuxTunChannel (tunDevice);
    logger.fine("Success constructing and mapping tun0");
    inputChannel = netDevice;
    outputChannel = netDevice;
  }

  /* (non-Javadoc)
   * @see java.lang.Runnable#run()
   */
  @Override
  public void run() {
    logger.info("Listening for IPv6 packets");
    final ByteBuffer buffer = ByteBuffer.allocateDirect(32767);
    try {
      while (true) {
        readAndVerifyIpv6Packet(buffer);
        if (!handleIPv6Packet(buffer)) {
          if (passUnHandled) {
            logger.finer(() -> "Passing packet to stdout");
            passOnChannel.write(buffer);
          } else {
            logger.log(Level.WARNING, "Unsupported IPv6 address referred from incoming IPv6 packet");
          }
        }
      }
    } catch (Exception e) {
      logger.log(Level.WARNING, "Exception in IPv6 reader thread", e);
    } finally {
      logger.log(Level.FINE, "IPv6 listener stopping");
      try {
        inputChannel.close();
      } catch (IOException e) {
        logger.log(Level.WARNING, "Cannot close input stream", e);
      }
      try {
        outputChannel.close();
      } catch (IOException e) {
        logger.log(Level.WARNING, "Cannot close output stream", e);
      }
      logger.log(Level.INFO, "IPv6 listener stopped");
    }
  }

  /**
   * Helper function to read exactly one packet.
   * @param buffer
   * @param ic
   * @throws IOException
   */
  private void readAndVerifyIpv6Packet(ByteBuffer buffer) throws IOException {
    buffer.clear();
    // read packet
    final int bytesRead = inputChannel.read(buffer);
    if (bytesRead < 0)
      throw new IOException("EOF flagged from input stream during read of header block");
    if (bytesRead < IPV6PACKET_HEADER_LENGTH)
      throw new IOException("Not even a full header read");
    buffer.flip();
    final int packetSize = verifyHeaderReturnPacketLength(buffer);
    if (buffer.remaining() != packetSize + IPV6PACKET_HEADER_LENGTH) {
      throw new IOException("Packet size from header " + packetSize + " is inconsistent with read packet length " + bytesRead);
    }
    logger.finer(() -> "Received packet, size " + buffer.remaining());
  }

  private ByteBuffer javaArrayBuffer = ByteBuffer.allocate(32767);

  /**
   * Write the IPv6 packet to the corresponding DTLS session (i.e. the object with the client IPv6
   * address that is receiver of the packet).
   * 
   * @param buffer the ByteBuffer containing the packet. Position() points to the first byte to use, limit() after
   *        the last one.
   * @return a boolean indicating if the supplied packet was found to be valid and could be sent. 
   * @throws IOException in case of communication problems.
   */
  private boolean handleIPv6Packet(ByteBuffer buffer) {
    byte[] addr = new byte[16];
    buffer.slice().position(IPV6PACKET_DESTINATION_OFFSET).get(addr);
    // TODO in java 16, replace by buffer.get (buffer.position() + IPV6PACKET_DESTINATION_OFFSET, addr);

    Inet6Address receiver;
    try {
      receiver = (Inet6Address) Inet6Address.getByAddress(addr);
    } catch (UnknownHostException e1) {
      logger.info("Illegal length of IP address - discarding");
      return false;
    }
    DTLSTransport dtlsServer;
    try {
      dtlsServer = dtlsData.getServer(receiver);
    } catch (NoSuchObjectException e) {
      return false;
    }
        
    try {
      int mtu = dtlsServer.getSendLimit();
      if (buffer.remaining() > mtu) {
        sendPacketTooBig(receiver, mtu);
      } else if (buffer.hasArray()) {
        logger.fine(()->"About to send " + buffer.remaining() + " bytes from array-backed buffer to dtls");
        dtlsServer.send(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
        buffer.position(buffer.limit());
      } else {
        logger.fine(()->"About to send " + buffer.remaining() + " bytes from direct buffer to dtls");

        synchronized (javaArrayBuffer) {
          javaArrayBuffer.clear();
          javaArrayBuffer.put(buffer);
          logger.finer(()->"About to send copied " + javaArrayBuffer.position() + " bytes to dtls");
          logger.finest(()->"Buffer content: " +
            new String(Hex.encode(javaArrayBuffer.array(), javaArrayBuffer.arrayOffset(), javaArrayBuffer.position()))
          );
          dtlsServer.send(javaArrayBuffer.array(), javaArrayBuffer.arrayOffset(), javaArrayBuffer.position());
        }
      }
    } catch (TlsFatalAlert e) {
      logger.log(Level.WARNING, "Fatal signal from DTLS engine, client session died for " + receiver, e);
      dtlsData.removeServer(receiver);
      return false;
    } catch (IOException e) {
      logger.log(Level.WARNING, "Handling of packet caused IO exception, client session might recover", e);
      return true;
    }
    logger.log(Level.FINE, "Send IPv6 packet for address {0} to {1}", new Object[] {receiver, dtlsServer});
    return true;
  }

  private void sendPacketTooBig(Inet6Address receiver, int mtu) {
    // TODO create ICMP packet too big packet (ICMP type 2)
    logger.warning("Unimplemented: too big packet recieved");
  }

  /**
   * Write an IPv6 packet to tun device. Packet starts at buffer's position and ends before buffer's limit.
   * @param bb The ByteBuffer containing the packet
   */
  @Override
  public void write(ByteBuffer bb) throws IOException {
    int contentLength = (int)verifyHeaderReturnPacketLength(bb);
    if (contentLength + IPv6InputHandler.IPV6PACKET_HEADER_LENGTH != bb.remaining()) {
      throw new IOException("Retrieved data do not represent a single IPv6 package " + dumpHeader(bb));
    }
    
    outputChannel.write(bb);
  }

  /**
   * @param bb a buffer supposed to contain a full 40 bytes IPv6 header
   * @return a short indicating the size of the packet, not including the 40 bytes IPv6 header.
   * @throws IOException
   */
  public short verifyHeaderReturnPacketLength(ByteBuffer bb) throws IOException {
    if (bb.remaining() < IPV6PACKET_HEADER_LENGTH) {
      throw new IOException("Supplied packet ist too short even for an IPv6 header\n  " + dumpHeader(bb) + "\n");
    }
    byte version = (byte)(bb.get(bb.position() + IPV6PACKET_PROTOCOL_BYTE_OFFSET) >>> IPV6PACKET_PROTOCOL_BIT_OFFSET);
    if (version != 6) {
      throw new IOException("Received non IPv6 packet - discarding\n  " + dumpHeader(bb) + "\n");
    }
    

    short len = bb.getShort(bb.position() + IPV6PACKET_LENGTH_OFFSET);
    if (len < 0) {
      throw new IOException("Invalid packet length in supposed IPv6 packet\n  " + dumpHeader(bb) + "\n");
    }
    return len;
  }

  /**
   * Convert first 40 bytes of buffer to hex string for debug purposes
   * @param bb the ByteBuffer to dump, position and limit setting boudary of dump
   * @return String representing buffer as hexadecimal string
   */
  private String dumpHeader(ByteBuffer bb) {
    StringBuilder sb = new StringBuilder(80);
    for (int i = bb.position(); i < bb.limit() && i < 40; i++) {
      if ((i%8) == 0)
        sb.append('\n');
      sb.append(String.format("%2x ", bb.get(i)));
    }
    return sb.toString();
  }

  @Override
  public void close() throws Exception {
    
  }
}
