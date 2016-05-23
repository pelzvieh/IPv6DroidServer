/*
 * Copyright (c) 2013 Dr. Andreas Feldner.
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU Lesser General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU Lesser General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Contact information and current version at http://www.flying-snail.de/IPv6Droid
 */

package de.flyingsnail.ipv6droid.ayiya;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.jdt.annotation.NonNull;

/**
 * AYIYA - Anything In Anything
 *
 * This realizes the tunnel protocol with the PoP in the SixXS network.
 *
 * Based on specifications published by SixXS, see
 * http://www.sixxs.net/tools/ayiya
 *
 */
public class AyiyaServer {

  /**
   * AYIYA version (which document this should conform to)
   */
  public static final String VERSION = "draft-02-subset";

  /** Tag for Logger */
  private static final String TAG = AyiyaServer.class.getName();

  // @todo I'm afraid I missed an official source for this kind of constants
  private static final byte IPPROTO_IPv6 = 41;
  private static final byte IPPROTO_NONE = 59;

  /** size of the AYIYA header */
  public static final int OVERHEAD = 44;

  private static final int MAX_TIME_OFFSET = 1000;

  /** The IPv6 address of the PoP, used as identity in the protocol. */
  private final Inet6Address ipv6Pop;

  /** the maximum transmission unit in bytes */
  private final int mtu;

  /** the maximum packet size */
  private int maxPacketSize = 0;

  /** The IPv4 address of the PoP - the only address we can send packets to. */
  private Inet4Address ipv4Pop;

  /** Our IPv6 address, in other words, the IPv6 endpoint of the tunnel. */
  private Inet6Address ipv6Local;

  /** The sha1 hash of the tunnel password */
  private byte[] hashedPassword;

  /** The v4 address/port pair of the tunnel client. */
  private SocketAddress remoteSocketAddress;

  /** The IPv6 outgoing stream */
  private OutputStream ipv6out = null;

  /** The IPv6 incoming stream */
  private InputStream ipv6in = null;

  /** keep track if a valid packet has been received yet. This is the final proof that the tunnel
   * is working.
   */
  private boolean validPacketReceived = false;

  /**
   * Count the number of invalid packets received.
   */
  private int invalidPacketCounter = 0;

  /**
   * The Date when a valid packet was last received from the tunnel (via write method!).
   */
  private Date lastPacketReceivedTime = new Date();

  /**
   * The Date when a valid packet was last returned to be written to the tunnel (via read method!).
   */
  private Date lastPacketSentTime = new Date();

  /**
   * Our Logger.
   */
  private Logger log;

  /**
   * Yield the time when the last packet was <b>received</b>. This gives an indication if the
   * tunnel is still alive.
   * @return a Date denoting the time of last packet received.
   */
  public Date getLastPacketReceivedTime() {
    return lastPacketReceivedTime;
  }

  /**
   * Yield the time when the last packet was <b>sent</b>. This gives an indication if we should
   * send an heartbeat packet.
   * @return a Date denoting the time of last packet sent.
   */
  public Date getLastPacketSentTime() {
    return lastPacketSentTime;
  }

  /**
   * Check if this object is in a functional state
   * @return a boolean, true if socket is still connected
   */
  public boolean isAlive() {
    return (ipv6out != null && ipv6in != null);
  }


  /**
   * The representation of our identity. This code supports INTEGER only.
   */
  enum Identity
  {
    NONE,  /* None */
    INTEGER,	/* Integer */
    STRING	/* ASCII String */
  }

  /**
   * The algorithm to calculate the hashes of datagrams. This code supports SHA1 only.
   */
  enum HashAlgorithm
  {
    NONE,	/* No hash */
    MD5,	/* MD5 Signature */
    SHA1,	/* SHA1 Signature */
    UMAC	/* UMAC Signature (UMAC: Message Authentication Code using Universal Hashing / draft-krovetz-umac-04.txt */
  }

  /**
   * The authentication type for datagrams. This code supports SHAREDSECRET only.
   */
  enum AuthType
  {
    NONE,	/* No authentication */
    SHAREDSECRED,	/* Shared Secret */
    PGP	/* Public/Private Key */
  }

  /**
   * The code of AYIYA operation. This code supports NOOP and FORWARD only.
   */
  enum OpCode
  {
    NOOP,	/* No Operation */
    FORWARD,	/* Forward */
    ECHO_REQUEST,	/* Echo Request */
    ECHO_REQUEST_FORWARD,	/* Echo Request and Forward */
    ECHO_RESPONSE,	/* Echo Response */
    MOTD,	/* MOTD */
    QUERY_REQUEST,	/* Query Request */
    QUERY_RESPONSE	/* Query Response */
  }


  /**
   * Constructor.
   * @param tunnel the specification of the tunnel to be dealt by this.
   */
  public AyiyaServer (TicTunnel tunnel) throws ConnectionFailedException {
    log = Logger.getLogger(TAG + " ["+tunnel.getTunnelName()+"]");
    if (!tunnel.isValid() || !tunnel.isEnabled())
      throw new IllegalStateException("Invalid or disabled tunnel specification supplied to Ayiya");
    // copy the information relevant for us in local fields
    ipv4Pop = tunnel.getIPv4Pop();
    ipv6Local = tunnel.getIpv6Endpoint();
    ipv6Pop = tunnel.getIpv6Pop();
    mtu = tunnel.getMtu();

    // we only need the hash of the password
    try {
      hashedPassword = ayiyaHash (tunnel.getPassword());
    } catch (NoSuchAlgorithmException e) {
      throw new ConnectionFailedException("Cannot hash password", e);
    } catch (UnsupportedEncodingException e) {
      throw new ConnectionFailedException("Cannot hash password", e);
    }
  }

  private static byte[] ayiyaHash (String s) throws NoSuchAlgorithmException, UnsupportedEncodingException {
    // compute the SHA1 hash of the password
    return ayiyaHash(s.getBytes("UTF-8"));
  }

  private static byte[] ayiyaHash (byte[] in) throws NoSuchAlgorithmException {
    // compute the SHA1 hash of the password
    MessageDigest sha1 = MessageDigest.getInstance("SHA1");
    sha1.update(in);
    return sha1.digest();
  }

  /**
   * Connect the tunnel.
   */
  public synchronized void connect(FileDescriptor fd, SocketAddress clientSocketAddress) throws IOException, ConnectionFailedException {
    if (ipv6out != null || ipv6in != null) {
      throw new IllegalStateException("This AYIYA is already connected.");
    }

    // set up the streams
    ipv6out = new FileOutputStream (fd);
    ipv6in = new FileInputStream(fd);
    remoteSocketAddress = clientSocketAddress;

    log.info("Ayiya tunnel to POP IP " + ipv4Pop + "created.");
  }

  /**
   * Re-Connect the tunnel, closing the existing socket
   */
  public synchronized void reconnect(FileDescriptor fd, SocketAddress clientSocketAddress) throws IOException, ConnectionFailedException {
    if (ipv6out == null || ipv6in == null)
      throw new IllegalStateException("Ayiya object is closed or not initialized");
    close();
    connect(fd, clientSocketAddress);
  }

  /**
   * Tell if a valid response has already been received by this instance.
   * @return true if any valid response was already received.
   */
  public boolean isValidPacketReceived() {
    // special situation: a packet was received, but is not yet read out - not the sender's
    // fault, really! Here, we ignore this situation, i.e. a tunnel might be classified
    // as troublemaker even if just the receiver thread died.
    return validPacketReceived;
  }

  /**
   * Return the number of invalid packages received yet.
   * @return an int representing the number.
   */
  public int getInvalidPacketCounter() {
    return invalidPacketCounter;
  }

  /**
   * Get the maximum transmission unit (MTU) associated with this Ayiya instance.
   * @return the MTU in bytes
   */
  public int getMtu() {
    return mtu;
  }

  /**
   * Send a heartbeat to the PoP
   */
  public void beat(DatagramSocket socket) throws IOException, TunnelBrokenException {
    if (ipv6out == null)
      throw new IOException("beat() called on unconnected Ayiya");
    byte[] ayiyaPacket;
    try {
      ayiyaPacket = buildAyiyaStruct(new byte[0], OpCode.NOOP,  IPPROTO_NONE);
    } catch (NoSuchAlgorithmException e) {
      log.log(Level.SEVERE, "SHA1 no longer available???", e);
      throw new TunnelBrokenException("Cannot build ayiya struct", e);
    }
    DatagramPacket dgPacket = new DatagramPacket(ayiyaPacket, ayiyaPacket.length, socket.getRemoteSocketAddress());
    socket.send(dgPacket);
    lastPacketSentTime = new Date();
  }

  /**
   * Create a byte from to 4 bit values.
   */
  private static byte buildByte(int val1, int val2) {
    return (byte)((val2 & 0xF) + ((val1 & 0xF) << 4));
    // this should be equiv. to C bitfield behaviour in big-endian machines
  }

  private byte[] buildAyiyaStruct(byte[] payload, OpCode opcode, byte nextHeader) throws NoSuchAlgorithmException {
    byte[] retval = new byte[payload.length + OVERHEAD];
    ByteBuffer bb = ByteBuffer.wrap (retval);
    bb.order(ByteOrder.BIG_ENDIAN);
    MessageDigest sha1 = MessageDigest.getInstance("SHA1");
    // first byte: idlen (=4, 2^4 = length of IPv6 address) and idtype
    bb.put(buildByte(4, Identity.INTEGER.ordinal())).
    // 2nd byte: signature length (5*4 bytes = SHA1) and hash method
    put(buildByte(5, HashAlgorithm.SHA1.ordinal())).
    // 3rd byte: authmeth and opcode
    put(buildByte(AuthType.SHAREDSECRED.ordinal(), opcode.ordinal())).
    // 4th byte: next header
    put(nextHeader).
    // 5th-8th byte: epoch time
    putInt((int) ((new Date().getTime()) / 1000l)).
    // 9th-24th byte: Identity
    put(ipv6Local.getAddress())
    ;

    // update the message digest with the bytes so far
    int hashStart = bb.position();
    sha1.update(bb.array(), 0, hashStart);

    // standard ayiya header now finished

    // 25th byte - 44th byte sha1 hash

    // now hash and buffer content diverge. We need to calculate the hash first, because it goes here
    sha1.update(hashedPassword);
    sha1.update(payload);
    byte[] hash = sha1.digest();
    assert(hash.length == 20);

    // now complete the buffer, with hash...
    bb.put(hash);
    // ...and payload
    bb.put(payload);

    return retval;
  }

  /**
   * Write next packet from the tunnel to the IPv6 device.
   * @param bb a ByteBuffer representing a read packet, with current position set to beginning of the <b>payload</b> and end set to end of payload.
   * @throws IOException in case of network problems (probably temporary in nature)
   * @throws IllegalArgumentException in case that the supplied ByteBuffer is trivially invalid. Packets failing to verify
   *    signature are not flagged by Exception, but instead increase invalidPacketCounter.
   */
  public void write(ByteBuffer bb) throws IOException, IllegalArgumentException {
    if (ipv6in == null)
      throw new IllegalStateException("read() called on unconnected Ayiya");

    int bytecount = bb.limit();

    // first check some pathological results for stability reasons
    if (bytecount > maxPacketSize)
      maxPacketSize = bytecount;
    if (bytecount <= OVERHEAD) {
      throw new IllegalArgumentException("received too short packet", null);
    } else if (bytecount == bb.capacity()) {
      log.log(Level.WARNING, "WARNING: maximum size of buffer reached - indication of a MTU problem");
    }

    // update timestamp of last packet received
    lastPacketReceivedTime = new Date();

    // check buffer content
    bb.limit(bytecount);
    bb.position(OVERHEAD);
    if (checkValidity(bb.array(), bb.arrayOffset(), bb.limit())) {
      OpCode opCode = getSupportedOpCode(bb.array(), bb.arrayOffset(), bb.limit());
      validPacketReceived = validPacketReceived || (opCode != null);
      // note: this flag must never be reset to false!
      if (opCode == OpCode.FORWARD) {
        ipv6out.write(bb.array(), bb.arrayOffset() + bb.position(), bytecount-bb.position());
        ipv6out.flush();
      } else if (opCode == OpCode.ECHO_RESPONSE) {
        log.log(Level.INFO, "Received valid echo response");
      } else
        invalidPacketCounter++;
    } else {
      invalidPacketCounter++;
    }
  }

  private static OpCode getSupportedOpCode (byte[] packet, int offset, int bytecount) {
    if (bytecount < 3) {
      Logger.getLogger(TAG).log(Level.WARNING, "Received too short package");
      return null;
    }

    try {
      int opCodeOrdinal = packet[2+offset] &0xF;
      return OpCode.values()[opCodeOrdinal];
    } catch (IndexOutOfBoundsException e) {
      return null;
    }
  }

  /**
   * Perform packet checks that do not depend on the actual tunnel. If valid return the tunnel ID.
   * TODO switch to a ByteBuffer parameter.
   * @param packet the byte[] containing the packet to check
   * @param offset the int giving the offset of packet start within the array
   * @param bytecount the int giving the length of the packet
   * @return Inet6Address of the tunnel to which this packet is related, null otherwise
   */
  public static Inet6Address precheckPacket (byte[] packet, int offset, int bytecount) {
    Logger log = Logger.getLogger(TAG);
    // check if the size includes at least a full ayiya header
    if (bytecount < OVERHEAD) {
      log.log(Level.WARNING, "Received too short package, skipping");
      return null;
    }

    // check if correct AYIYA packet
    if (buildByte(4, Identity.INTEGER.ordinal()) != packet[offset] ||
        buildByte(5, HashAlgorithm.SHA1.ordinal()) != packet[1+offset] ||
        AuthType.SHAREDSECRED.ordinal() != (packet[2+offset] >> 4) ||
        (getSupportedOpCode(packet, offset, bytecount) == null) ||
        ((packet[3+offset] != IPPROTO_IPv6) && (packet[3+offset] != IPPROTO_NONE))
        ) {
      log.log(Level.WARNING, "Received packet with invalid ayiya header, skipping");
      return null;
    }

    // check time
    ByteBuffer bb = ByteBuffer.wrap(packet, 4+offset, 4);
    int epochTimeRemote = bb.getInt();
    int epochTimeLocal = (int) (new Date().getTime() / 1000);
    if (Math.abs(epochTimeLocal - epochTimeRemote) > MAX_TIME_OFFSET) {
      log.log(Level.WARNING, "Received packet from " + (epochTimeLocal-epochTimeRemote) + " in the past");
      return null;
    }
    
    // extract sender IP (== tunnel ID)
    Inet6Address sender = null;
    try {
      sender = (Inet6Address)Inet6Address.getByAddress(Arrays.copyOfRange(packet, 8+offset, 24+offset));
    } catch (UnknownHostException e) {
      log.log(Level.SEVERE, "UnknownHostException when converting a byte array to Inet6Address", e);
    }

    return sender;
  }

  private boolean checkValidity(byte[] packet, int offset, int bytecount) {
    // @todo refactor these checks, they look awful and are co-variant with buildAyiyaStruct.
    // @todo never tested with offset > 0, if this part is ever going to be a library, you have to.
    // check if correct sender id. Strictly speaking not correct, as the sender could use our
    // id. This is considered valid here because in assertion mode we're using this method for
    // our own packets as well.
    Inet6Address sender = precheckPacket(packet, offset, bytecount);
    if (sender == null || (!sender.equals(ipv6Pop) && !sender.equals(ipv6Local))) {
      log.log(Level.WARNING, "Received packet from invalid sender id " + sender);
      return false;
    }

    // check signature
    byte[] theirHash = Arrays.copyOfRange(packet, 24+offset, 44+offset);

    MessageDigest sha1;
    try {
      sha1 = MessageDigest.getInstance("SHA1");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unable to do sha1 hashes", e);
    }
    sha1.update(packet, offset, 24);
    sha1.update(hashedPassword);
    sha1.update(packet, 44+offset, bytecount-44);
    byte[] myHash = sha1.digest();
    if (!Arrays.equals(myHash, theirHash)) {
      log.log(Level.WARNING, "Received packet with failed hash comparison");
      return false;
    }

    // check ipv6
    if (packet[3+offset] == IPPROTO_IPv6 && bytecount >= OVERHEAD && (packet[OVERHEAD +offset] >> 4) != 6) {
      log.log(Level.WARNING, "Payload should be an IPv6 packet, but isn't");
      return false;
    }

    // this packet appears to be valid!
    return true;
  }

  /**
   * Reads a packet from IPv6, wraps it into a v4 datagram and returns the packet that should be written to the tunel.
   * @param payload the payload to send (an IP packet itself...)
   * @throws IOException in case of network problems (probably temporary in nature)
   * @throws TunnelBrokenException in case that this tunnel is no longer usable and must be restarted
   */
  public void read(DatagramSocket socket) throws IOException {
    if (ipv6in == null)
      throw new IllegalStateException("write(byte[]) called on unconnected Ayiya");

    byte[] payload = new byte[1500];
    ipv6in.read(payload);

    byte[] ayiyaPacket;
    try {
      ayiyaPacket = buildAyiyaStruct(payload, OpCode.FORWARD, IPPROTO_IPv6);
    } catch (NoSuchAlgorithmException e) {
      log.log(Level.SEVERE, "SHA1 no longer available???", e);
      throw new IllegalStateException("Cannot build ayiya struct", e);
    }
    assert(checkValidity(ayiyaPacket, 0, ayiyaPacket.length));
    DatagramPacket dgPacket = new DatagramPacket(ayiyaPacket, ayiyaPacket.length, remoteSocketAddress);
    socket.send(dgPacket);
    lastPacketSentTime = new Date();
  }

  private class AyiyaOutputStream extends OutputStream {
    @Override
    public void write(@NonNull byte[] buffer) throws IOException {
      try {
        ByteBuffer bb = ByteBuffer.wrap(buffer);
        AyiyaServer.this.write(bb);
      } catch (IllegalArgumentException e) {
        throw new IOException(e);
      }
    }

    @Override
    public void write(@NonNull byte[] buffer, int offset, int count) throws IOException {
      this.write(Arrays.copyOfRange(buffer, offset, offset + count));
    }

    @Override
    public void write(int i) throws IOException {
      this.write(new byte[] {(byte)i});
    }
  }

  /**
   * Provides an OutputStream on the tunnel. Any write should give a whole tcp package to transmit.
   * @return the OutputStream
   */
  public OutputStream getOutputStream() {
    return new AyiyaOutputStream();
  }

  /**
   * Close our socket. Basically that's about it.
   */
  public synchronized void close() {
    if (ipv6in != null)
      try {
        ipv6in.close();
      } catch (IOException e) {
        log.log(Level.WARNING, "Couldn't close input stream", e);
      }
    if (ipv6out != null) {
      try {
        ipv6out.close();
      } catch (IOException e) {
        log.log(Level.WARNING, "Couldn't close output stream", e);
      }
    }
    ipv6in = null; // it's useless anyway
    ipv6out = null;
  }
}
