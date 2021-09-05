/**
 * Copyright (c) 2021 Dr. Andreas Feldner (pelzi).
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
package de.flyingsnail.tun;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.util.encoders.Hex;

import com.sun.jna.LastErrorException;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.platform.linux.Fcntl;


/**
 * @author pelzi
 *
 */
public class LinuxTunChannel implements AutoCloseable, ReadableByteChannel, WritableByteChannel {

  public static final String DEV_NET_TUN = "/dev/net/tun";
  private static final short IFF_TUN = 0x001;
  private static final short IFF_NO_PI = 0x1000;
  private static final int TUNSETIFF = (1  << 30) | ('T' << 8) | (202 << 0) | (4 << 16);
  private Logger logger = Logger.getLogger(getClass().getName());
  
  // JNA magic of higher order. We sort of import the glibc of our plattform
  static {
    Native.register(Platform.C_LIBRARY_NAME);
  }
  
  public static native int open (String name, int mode) throws LastErrorException;
  public static native int close(int fd) throws LastErrorException;
  public static native int read(int fd, ByteBuffer b, int count) throws LastErrorException;
  public static native int write(int fd, ByteBuffer b, int count) throws LastErrorException;
  public static native int ioctl(int fd, int request, ByteBuffer args) throws LastErrorException;

  /**
   * The unix file descriptor that's the base of this class.
   */
  private int fd;
  
  /**
   * Our internal buffer if the caller passes non-direct ByteBuffer.
   */
  private ByteBuffer directBB = ByteBuffer.allocateDirect(32767);
  
  /**
   * we need a direct ByteBuffer
   */
  
  /**
   * Open a TUN network device and provide input and output channels for that.
   * @param deviceName a String giving the network device name that should be mapped to this tun device.
   */
  public LinuxTunChannel(String deviceName) throws IOException {
    logger.info(()->"Constructing for " + deviceName);
    fd = allocateTunDevice(deviceName);
  }

  @Override
  public void close() throws IOException {
    logger.info("Closing");
    if (fd > 0 && close(fd) != 0) {
      throw new IOException ("Could not close unix fd");
    }
    fd = 0;
  }
  
  
  /*private interface CStdLib extends Library {
    int ioctl(int fd, int request, Object... args);
    int open (String name, int mode);
  };
  private CStdLib glibC = Native.load(CStdLib.class);*/
  
  private class IfReq {
    private ByteBuffer bb = ByteBuffer.allocateDirect(32);
    public synchronized void setIfName (String ifName) throws UnsupportedEncodingException {
      if (ifName.length() >= 16) {
        throw new IllegalArgumentException("network interface name must not exceed 15 chars");
      }
      bb.put(ifName.getBytes("ISO-8859-1"));
      bb.put((byte)0);
      bb.position(0);
    }
    
    public synchronized void setFlags(short flags) {
      bb.order(ByteOrder.nativeOrder());
      bb.putShort(16, flags);
    }
    
    public synchronized ByteBuffer asBuffer() {
      return bb.slice();
    }
  }
  
  /**
   * Open TUN device and map it to the given network device.
   * @param deviceName a String giving the network device name that should be mapped.
   *    If you pass null, a test mode is used and this will just point to /dev/null.
   * @return an int giving the Unix file descriptior
   * @throws IOException in case that the device could not be opened or mapped.
   */
  private int allocateTunDevice(final String deviceName) throws IOException  {
    String fileName = (deviceName != null) ? DEV_NET_TUN : "/dev/zero";
    logger.finer(() -> "About to open "+fileName);
    int fd;
    try {
      fd = open(fileName, Fcntl.O_RDWR);
    } catch (LastErrorException errno) {
      throw new IOException (errno);
    }
    if (fd < 0) {
      throw new IOException("Unable to open " + fileName);
    }
    logger.fine(()->"Open succeeded, fd="+fd);

    if (deviceName == null) {
      return fd;
    }
    
    try {
      IfReq ifreq = new IfReq();

      try {
        ifreq.setIfName(deviceName);
      } catch (UnsupportedEncodingException e) {
        throw new IllegalStateException ("This java VM does not support ISO-8859-1 encoding", e);
      }
      
      ifreq.setFlags((short) (IFF_TUN | IFF_NO_PI));

      logger.finer("About to perform ioctl " + TUNSETIFF + " on fd");
      try {
        // TODO remove debugging
        ByteBuffer ifreqBB = ifreq.asBuffer();
        ByteBuffer debug = ByteBuffer.allocate(ifreqBB.remaining());
        debug.put(ifreqBB.slice());
        Hex.encode(debug.array(), debug.arrayOffset(), debug.position(), System.err);
        System.err.println();
        if (ioctl(fd, TUNSETIFF, ifreq.asBuffer()) == -1) {
          throw new IOException("Could not map network device to file descriptor: " + deviceName);
        }
      } catch (LastErrorException errno) {
        throw new IOException (errno);
      }

      logger.fine("ioctl 202 succeeded on fd " + fd);
    } catch (Throwable t) {
      try {
        close();
      } catch (IOException e) {
        logger.log(Level.WARNING, "Could not close unix fd after failure in initialiser", t);
      }
      throw t;
    }
    return fd;
  }
  @Override
  public boolean isOpen() {
    return (fd > 0);
  }
  
  /**
   * <p>Write an IP packet from the given buffer to the TUN device.</p>
   * <p><b>Note that this channel work packet-wise, not stream-wise:</b>
   * The buffer is supposed to contain exactly one full packet.
   * @param src a ByteBuffer containing one single IP packet
   * @return an int giving the number of bytes written
   */
  @Override
  public int write(ByteBuffer src) throws IOException {
    if (src.remaining() <= 0) {
      return 0;
    }
    
    if (src.isDirect()) {
      logger.fine(()->"About to write " + src.remaining() + " bytes from direct buffer to network device");
      int bytesWritten;
      try {
        bytesWritten = write (fd, src, src.remaining());
      } catch (LastErrorException errno) {
        throw new IOException (errno);
      }
      if (bytesWritten < 0) {
        throw new IOException ("Error writing to fd "+ fd);
      }
      logger.finest(()->"Successfully wrote " + bytesWritten + " bytes to network device");
      
      src.position(src.position() + bytesWritten);
      return bytesWritten;
    } else {
      logger.fine(()->"About to write " + src.remaining() + " bytes from non-direct buffer to network device");

      synchronized (directBB) {
        directBB.clear();
        directBB.put(src);
        directBB.flip();
        // no danger of recursion - directBB is a direct ByteBuffer
        // we have optimum performance in case a direct ByteBuffer is passed
        return write (directBB);
      }
    }    
  }
  

  /**
   * <p>Read the next IP packet from the TUN device to the supplied buffer.
   * Works most efficient if the buffer is a "direct" buffer.</p>
   * <p><b>Note that this channel behaves packet-wise, not stream-wise:</b> 
   * If your buffer is too small to receive the full packet, the remainder
   * will be unrecoverably lost. The next call will return the next packet.</p>
   * @param dst a ByteBuffer to receive the packet. Reading starts at position and
   *      ends at the byte before limit. On return, the buffer's position is advanced to the
   *      byte following the last read byte.
   * @return an int giving the number of bytes read.
   */
  @Override
  public int read(ByteBuffer dst) throws IOException {
    if (dst.remaining() <= 0) {
      return 0;
    }
    if (dst.isDirect()) {
      logger.fine(() -> "About to read " + dst.remaining() + " bytes from network device to direct buffer");
      int bytesRead;
      try {
        bytesRead = read (fd, dst, dst.remaining());
      } catch (LastErrorException errno) {
        throw new IOException (errno);
      }
      if (bytesRead < 0) {
        throw new IOException ("Error reading from fd "+ fd);
      }
      logger.finer(() -> "Successfully read " + bytesRead + " bytes from network device");
      dst.position(dst.position() + bytesRead);
      return bytesRead;
    } else {
      synchronized (directBB) {
        logger.fine(() -> "About to read " + dst.remaining() + " bytes from network device to non-direct buffer");

        directBB.clear();
        directBB.limit(dst.remaining());
        // no danger of recursion - directBB is a direct ByteBuffer
        // we have optimum performance in case a direct ByteBuffer is passed
        int bytesRead = read(directBB);
        directBB.flip();
        dst.put(directBB);
        return bytesRead;
      }
    }    
  }
}
