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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.rmi.NoSuchObjectException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.TlsFatalAlert;
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
    
  private Logger logger = Logger.getLogger(getClass().getName());
  
  private @NonNull DTLSData dtlsData;

  private boolean passUnHandled;

  final ForkJoinPool executorPool = new ForkJoinPool();
 
  private Future<InputStream> inputStream;
  
  private Future<OutputStream> outputStream;
  
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
    inputStream = executorPool.submit(() -> tunPipe.getInputStream());
    outputStream = executorPool.submit(() -> tunPipe.getOutputStream());
    
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

  public IPv6InputHandler(DTLSData dtlsData, File input, File output, Boolean passThrough) throws IllegalStateException {
    this (dtlsData, passThrough);
    logger.info(() -> "Constructing pipe based IPv6InputHandler on " + input + " and " + output);
    // set input and output streams
    outputStream = executorPool.submit(() -> new FileOutputStream(output));
    inputStream = executorPool.submit(() -> new FileInputStream(input));
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
    ByteBuffer lengthBytes = ByteBuffer.allocate(2);
    try {
      final InputStream is = inputStream.get();
      while (true) {
        // tuntopipe writes two bytes length information
        lengthBytes.clear();
        int bytesRead = is.read(lengthBytes.array(), lengthBytes.arrayOffset(), 2);
        if (bytesRead < 0)
          break;
        if (bytesRead != 2)
          throw new IllegalStateException ("Did not read two bytes of length indicator - probably lost stream sync");
        lengthBytes.limit(2);
        short length = lengthBytes.getShort();
        buffer.clear();
        if (length < 40 || length > buffer.capacity()) {
          throw new IllegalStateException("Got illegal length information - probably lost stream sync: 0x" + 
              String.format("%4x", length));
        }
        buffer.limit(buffer.position() + length);
        bytesRead = is.read(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
        if (bytesRead < 0)
          break;
        if (bytesRead != length)
          throw new IllegalStateException ("Did not read indicated number of bytes of IP package - probably lost stream sync");
        logger.finer(() -> "Received packet, size " + length);
        if (!handleIPv6Packet(buffer)) {
          if (passUnHandled) {
            logger.finer(() -> "Passing packet to stdout");
            System.out.write(lengthBytes.array(), lengthBytes.arrayOffset(), 2);
            System.out.write (buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
            System.out.flush();
          } else {
            logger.log(Level.WARNING, "Unsupported IPv6 address referred from incoming IPv6 packet");
          }
        }
      }
    } catch (Exception e) {
      logger.log(Level.WARNING, "Exception in IPv6 reader thread", e);
    } finally {
      try {
        inputStream.get().close();
      } catch (IOException | InterruptedException | ExecutionException e) {
        logger.log(Level.WARNING, "Cannot close input stream", e);
      }
      try {
        outputStream.get().close();
      } catch (IOException | InterruptedException | ExecutionException e) {
        logger.log(Level.WARNING, "Cannot close output stream", e);
      }
    }
  }

  /**
   * Write the IPv6 packet to the corresponding DTLS session (i.e. the object with the client IPv6
   * address that is receiver of the packet).
   * 
   * @param buffer the ByteBuffer containing the packet. Position() points to the first byte to use, limit() after
   *        the last one.
   * @throws IOException in case of communication problems.
   */
  private boolean handleIPv6Packet(ByteBuffer buffer) {
    buffer = buffer.slice().mark();
    byte version = (byte)((buffer.get() >> 4) & 0xf); // die 4 ersten bits des Packets sollen die IP-Version sein
    if (version != 6) {
      logger.warning("Received non IPv6 packet - discarding");
      return false;
    }
    buffer.position(buffer.position() + 23);
    
    byte[] addr = new byte[16];
    buffer.get (addr);
    buffer.reset();
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
    short len = (short)bb.remaining();
    OutputStream os;
    try {
      os = outputStream.get();
    } catch (InterruptedException | ExecutionException e) {
      throw new IOException (e);
    }
    synchronized (os) {
      // write the length
      os.write (len >> 8); // masking is done by the write method already
      os.write (len);
      // write the packet
      os.write(bb.array(), bb.arrayOffset() + bb.position(), bb.remaining());
      os.flush();
    }
  }


}
