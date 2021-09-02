/*
 * Copyright (c) 2016 Dr. Andreas Feldner.
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
package de.flyingsnail.ipv6server.dtlstransporter;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * This interface represents a class that will accept ByteBuffers, one at a time, through its write method.
 * The write method is guaranteed to be thread-safe.
 * 
 * @author pelzi
 *
 */
public interface BufferWriter {
  /**
   * Write a ByteBuffer to this class for further handling (unspecified what it is). The position() and limit()
   * properties indicate start and end of the byte region that should be handled.<p>
   * This method will not alter the ByteBuffer supplied.<p>
   * This method is thread-safe in whatever it does.<p>
   * 
   *     Impl hint    (bb.array(), bb.arrayOffset() + bb.position(), bytecount-bb.position());
        ipv6out.flush();

   * @param bb a ByteBuffer with position set to the beginning and limit() set to the end of the area of interest.
   * @throws IOException in case of a communication problem
   */
  public void write(ByteBuffer bb) throws IOException;
  
  /**
   * @param bb a ByteBuffer containing an IPv6 packet at its position.
   * @return List&lt;ByteBuffer&gt; an ordered list of ByteBuffers sliced from bb, each representing
   *         start and end of a single IPv6 packet.
   * @throws IOException in case of buffer not representing an IPv6 packet, length mismatch of
   *         buffer remaining and the packet size as indicated by the packet itself
   */
  public List<ByteBuffer> cutConsistentIPv6(ByteBuffer bb) throws IOException;
}
