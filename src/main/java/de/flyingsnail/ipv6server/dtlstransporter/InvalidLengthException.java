/**
 * Copyright (c) 2019 Dr. Andreas Feldner (pelzi).
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

/**
 * Gets thrown if a packet doesn't pass basic length checks.
 * 
 * @author pelzi
 *
 */
public class InvalidLengthException extends InvalidIPv4PacketException {

  /**
   * 
   */
  private static final long serialVersionUID = -3161587344400839136L;

  /**
   * Default constructor
   */
  public InvalidLengthException() {
  }

  /**
   * @param message a String describing the problem
   */
  public InvalidLengthException(String message) {
    super(message);
  }

  /**
   * @param cause a Throwable indicating a lower level Exception that led to this exception
   */
  public InvalidLengthException(Throwable cause) {
    super(cause);
  }

  /**
   * @param message a String describing the problem
   * @param cause a Throwable indicating a lower level Exception that led to this exception
   */
  public InvalidLengthException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message a String describing the problem
   * @param cause a Throwable indicating a lower level Exception that led to this exception
   * @param enableSuppression a boolean describing if suppression should be enabled :-)
   * @param writableStackTrace a boolean describing if the stack trace is writable
   */
  public InvalidLengthException(String message, Throwable cause,
      boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
