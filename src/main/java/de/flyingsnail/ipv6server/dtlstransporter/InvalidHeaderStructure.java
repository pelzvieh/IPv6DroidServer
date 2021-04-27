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
 * This is thrown when a received IPv6 packet does not pass structure checks.
 * @author pelzi
 *
 */
public class InvalidHeaderStructure extends InvalidIPv4PacketException {

  /**
   * 
   */
  private static final long serialVersionUID = -2167667525264162597L;

  /**
   * 
   */
  public InvalidHeaderStructure() {
  }

  /**
   * @param message a String describing the problem
   */
  public InvalidHeaderStructure(String message) {
    super(message);
  }

  /**
   * @param cause a Throwable indicating a lower level Exception that led to this exception
   */
  public InvalidHeaderStructure(Throwable cause) {
    super(cause);
  }

  /**
   * @param message a String describing the problem
   * @param cause a Throwable indicating a lower level Exception that led to this exception
   */
  public InvalidHeaderStructure(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message a String describing the problem
   * @param cause a Throwable indicating a lower level Exception that led to this exception
   * @param enableSuppression a boolean describing if suppression should be enabled :-)
   * @param writableStackTrace a boolean describing if the stack trace is writable
   */
  public InvalidHeaderStructure(String message, Throwable cause,
      boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

}
