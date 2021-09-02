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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.rmi.NoSuchObjectException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.jdt.annotation.NonNull;

/**
 * IPv6InputHandler constantly reads IP packets from the IPv6 input sourceType. The underlying OS's routing
 * should be prepared in a way that ensures that these packets are each targeted at specific tunnel clients.
 * 
 * Currently, this uses an external helper program to bind to a linux tun device.
 *
 * @author pelzi
 *
 */
public class IPv6InputHandler implements Runnable, BufferWriter {
    
  private static final int IPV6PACKET_DESTINATION_OFFSET = 24;

  private static final int IPV6PACKET_HEADER_LENGTH = 40;

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

  final ForkJoinPool executorPool = new ForkJoinPool();
 
  private ReadableByteChannel inputChannel;
  
  private WritableByteChannel outputChannel;

  private WritableByteChannel stdoutChannel;

  /**
   * Constructor
   * @param dtlsData the registry of DTLS sessions per IPv6 address
   * @param tunDevice the name of the tun device to read from via TUNTOPIPE.
   * @param passUnHandled a boolean indicating if unhandled packets from tun device should be written to stdout. In this case
   *                      this whole process can act as TUNTOPIPE for another IPv6 tunnel transporter.
   * @throws IllegalStateException in case of incorrectly deployed application, e.g. if TUNTOPIPE cannot be launched
   */
  private IPv6InputHandler (@NonNull DTLSData dtlsData, boolean passUnHandled) throws IllegalStateException {
    this.dtlsData = dtlsData;
    this.passUnHandled = passUnHandled;
    if (passUnHandled) {
      stdoutChannel = Channels.newChannel(System.out);
    }
  }

  public IPv6InputHandler(DTLSData dtlsData, String tunDevice, Boolean passThrough) throws IllegalStateException {
    this(dtlsData, passThrough);
    logger.info("Constructing process launching IPv6InputHandler");
    Process tunPipe;
    try {
      tunPipe = attachToTun(tunDevice);
    } catch (IOException e) {
      throw new IllegalStateException ("Cannot launch TUNTOPIPE. Check that it is installed and on the search path", e);
    }
  
    // set input and output streams
    inputChannel = Channels.newChannel(tunPipe.getInputStream());
    outputChannel = Channels.newChannel(tunPipe.getOutputStream());
    
    // launch an consumer on TUNTOPIPE's error stream to log its output
    Thread errLogger = new Thread (() -> {
      BufferedReader errorReader = new BufferedReader(new InputStreamReader(tunPipe.getErrorStream()));
      while (tunPipe.isAlive()) {
        try {
          logger.log(Level.INFO, "TUNTOPIPE: {0}", errorReader.readLine());
        } catch (IOException e) {
          logger.log(Level.WARNING, "IO exception on TUNTOPIPE error stream", e);
          try {
            Thread.sleep(1000l);
          } catch (InterruptedException e1) {
            try {
              errorReader.close();
            } catch (IOException e2) {
              // irrelevant
            }
            Thread.currentThread().interrupt(); // re-interrupt
          }
        }
      }
    }, "tuntopipe error logger");
    errLogger.setDaemon(true);
    errLogger.start();
  }

  public IPv6InputHandler(DTLSData dtlsData, Path input, Path output, Boolean passThrough) throws IllegalStateException, IOException {
    this (dtlsData, passThrough);
    logger.info(() -> "Constructing pipe based IPv6InputHandler on " + input + " and " + output);
    // set input and output streams, open in separate Threads, as one might block until the other is operational
    Future<FileChannel> outFuture = executorPool.submit(() -> FileChannel.open(output, Set.of(StandardOpenOption.APPEND)));
    Future<FileChannel> inFuture = executorPool.submit(() -> FileChannel.open(input, Set.of (StandardOpenOption.READ)));
    
    try {
      outputChannel = outFuture.get();
      inputChannel = inFuture.get();
    } catch (InterruptedException | ExecutionException e) {
      throw new IOException(e);
    }
  }

  private Process attachToTun(@NonNull final String tunDevice) throws IOException {
    // Construct reader
    ProcessBuilder pb = new ProcessBuilder("tuntopipe", "-i", tunDevice, "-u");
    if (logger.isLoggable(Level.FINEST)) {
      List<String> cmd = pb.command();
      cmd.add("-d");
      pb.command(cmd);
    }
    // launch
    logger.info(() -> "Launching TUNTOPIPE on interface " + tunDevice);
    pb.redirectErrorStream(false);
    return pb.start();    
  }

  /* (non-Javadoc)
   * @see java.lang.Runnable#run()
   */
  @Override
  public void run() {
    logger.info("Listening for IPv6 packets");
    ByteBuffer buffer = ByteBuffer.allocate(64*1024);
    try {
      final ReadableByteChannel ic = inputChannel;
      logger.fine("Retrieved input channel");
      while (true) {
        buffer.clear();
        int bytesRead = ic.read(buffer);
        if (bytesRead < 0)
          throw new IllegalStateException ("EOF flagged from input stream during read of data block");
        buffer.flip();
        logger.finer(() -> "Received packet, size " + buffer.remaining());
        for (ByteBuffer packet: cutConsistentIPv6(buffer)) {
          if (!handleIPv6Packet(packet)) {
            if (passUnHandled) {
              logger.finer(() -> "Passing packet to stdout");
              stdoutChannel.write(packet);
            } else {
              logger.log(Level.WARNING, "Unsupported IPv6 address referred from incoming IPv6 packet");
            }
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
    System.arraycopy(buffer.array(), buffer.position() + IPV6PACKET_DESTINATION_OFFSET + buffer.arrayOffset(),
        addr, 0, addr.length);
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
      dtlsServer.send(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
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

  /**
   * Write an IPv6 packet to tun device. Packet starts at buffer's position and ends before buffer's limit.
   * @param bb The ByteBuffer containing the packet
   */
  @Override
  public void write(ByteBuffer bb) throws IOException {
    List<ByteBuffer> packets = cutConsistentIPv6(bb);
    for (ByteBuffer packet: packets) {
      outputChannel.write(packet);
    }
  }

  /**
   * @param bb a ByteBuffer containing an IPv6 packet at its position.
   * @return List&lt;ByteBuffer&gt; an ordered list of ByteBuffers sliced from bb, each representing
   *         start and end of a single IPv6 packet.
   * @throws IOException in case of buffer not representing an IPv6 packet, length mismatch of
   *         buffer remaining and the packet size as indicated by the packet itself
   */
  public List<ByteBuffer> cutConsistentIPv6(ByteBuffer bb) throws IOException {
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
    if (bb.remaining() < len + IPV6PACKET_HEADER_LENGTH) {
      throw new IOException("Attempt to write buffer with inconsistent length information: buffer remaining does not match indicated payload size plus header length\n  " + dumpHeader(bb) + "\n");
    } else if (bb.remaining() > len + IPV6PACKET_HEADER_LENGTH) {
      List<ByteBuffer> chain = new LinkedList<ByteBuffer>();
      chain.add(bb.slice().limit(len + IPV6PACKET_HEADER_LENGTH));
      chain.addAll(cutConsistentIPv6(bb.slice().position(len + IPV6PACKET_HEADER_LENGTH)));
      return chain;
    } else {
      return Arrays.asList(bb);
    }
  }

  /**
   * Convert first 40 bytes of buffer to hex string for debug purposes
   * @param bb the ByteBuffer to dump, position and limit setting boudary of dump
   * @return String representing buffer as hexadecimal string
   */
  private String dumpHeader(ByteBuffer bb) {
    return Hex.toHexString(bb.array(), bb.arrayOffset() + bb.position(), Math.min(bb.remaining(), 40));
  }
}
