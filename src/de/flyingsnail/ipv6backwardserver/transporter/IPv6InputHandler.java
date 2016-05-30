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

package de.flyingsnail.ipv6backwardserver.transporter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.jdt.annotation.NonNull;

import de.flyingsnail.ipv6droid.ayiya.AyiyaServer;
import de.flyingsnail.ipv6droid.ayiya.BufferWriter;

/**
 * IPv6InputHandler constantly reads IP packets from the IPv6 input source. The underlying OS's routing
 * should be prepared in a way that ensures that these packets are each targeted at specific tunnel clients.
 * 
 * Currently, this uses an external helper program to bind to a linux tun device.
 *
 * @author pelzi
 *
 */
public class IPv6InputHandler implements Runnable, BufferWriter {
  
  private @NonNull String tunDevice;
  
  private Logger logger = Logger.getLogger(getClass().getName());
  
  private Process tunPipe;

  private @NonNull AyiyaData ayiyaData;

  public IPv6InputHandler (@NonNull AyiyaData ayiyaData, @NonNull String tunDevice) throws IllegalStateException {
    this.tunDevice = tunDevice;
    this.ayiyaData = ayiyaData;

    try {
      attachToTun();
    } catch (IOException e) {
      throw new IllegalStateException ("Cannot launch tuntopipe. Check that it is installed and on the search path", e);
    }
    
    // launch an consumer on tuntopipe's error stream to log its output
    Thread errLogger = new Thread (new Runnable() {
      @Override
      public void run() {
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(tunPipe.getErrorStream()));
        while (tunPipe.isAlive()) {
          try {
            logger.log(Level.FINEST, "tuntopip: " + errorReader.readLine());
          } catch (IOException e) {
            logger.log(Level.WARNING, "IO exception on tuntopipe error stream", e);
            try {
              Thread.sleep(1000l);
            } catch (InterruptedException e1) {
              // irrelevant
            }
          };
        }
      }
      
    }, "tuntopipe error logger");
    errLogger.setDaemon(true);
    errLogger.start();
  }

  private void attachToTun() throws IOException {
    // Construct reader
    ProcessBuilder pb = new ProcessBuilder("tuntopipe", "-i", tunDevice, "-u");
    if (logger.isLoggable(Level.FINEST)) {
      List<String> cmd = pb.command();
      cmd.add("-d");
      pb.command(cmd);
    }
    // launch
    logger.info("Launching tuntopipe on interface " + tunDevice);
    pb.redirectErrorStream(false);
    tunPipe = pb.start();    
  }

  /* (non-Javadoc)
   * @see java.lang.Runnable#run()
   */
  @Override
  public void run() {
    logger.info("Listening for IPv6 packets");
    ByteBuffer buffer = ByteBuffer.allocate(1500);
    byte[] lengthBytes = new byte[2];
    while (tunPipe.isAlive()) {
      InputStream ipv6Stream = tunPipe.getInputStream();
      try {
        // tuntopipe writes two bytes length information
        ipv6Stream.read(lengthBytes);
        int length = lengthBytes[0] * 16 + lengthBytes[1];
        buffer.clear();
        if (length < 40 || length > buffer.capacity())
          throw new IllegalStateException("Got illegal length information - probably lost stream sync");
        buffer.limit(buffer.position() + length);
        ipv6Stream.read(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
        logger.finer("Received packet, size " + length);
        handleIPv6Packet(buffer);
      } catch (Exception e) {
        logger.log(Level.WARNING, "Exception in IPv4 reader thread", e);
      }
    }
  }

  /**
   * Write the IPv6 packet to the corresponding AyiyaServer object (i.e. the object with the client IPv6
   * address that is receiver of the packet).
   * 
   * @param buffer the ByteBuffer containing the packet. Position() points to the first byte to use, limit() after
   *        the last one.
   * @throws IOException in case of communication problems.
   */
  private void handleIPv6Packet(ByteBuffer buffer) throws IOException {
    buffer.mark();
    if (buffer.get() != 6) {
      logger.warning("Received non IPv6 packet - discarding");
      return;
    }
    buffer.position(buffer.position() + 23);
    
    byte[] addr = new byte[16];
    buffer.get (addr);
    buffer.reset();
    Inet6Address receiver = (Inet6Address) Inet6Address.getByAddress(addr);
    AyiyaServer ayiyaServer = ayiyaData.getServer(receiver);
    if (ayiyaServer == null) {
      logger.warning("Unsupported IPv6 address referred from incoming IPv6 packet: " + receiver);
      return;
    }
    if (ayiyaServer.isConnected())
        ayiyaServer.writeToIPv4(buffer);
    else
      logger.fine("Packet received to an unconnected AyiyaServer");
  }

  /**
   * Write an IPv6 packet to tun device. Packet starts at buffer's position and ends before buffer's limit.
   * @param bb The ByteBuffer containing the packet
   */
  @Override
  public void write(ByteBuffer bb) throws IOException {
    short len = (short)bb.remaining();
    OutputStream os = tunPipe.getOutputStream();
    synchronized (os) {
      // write the length
      os.write (len >> 8); // masking is done by the write method already
      os.write (len);
      // write the packet
      os.write(bb.array(), bb.arrayOffset() + bb.position(), bb.remaining());
    }
  }


}
