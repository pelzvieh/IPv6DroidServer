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

package de.flyingsnail.ipv6backwardserver.directory;

/**
 * An exception indicating an failed attempt to authorize a user.
 * @author pelzi
 *
 */
public class AuthenticationFailedException extends Exception {

  private static final long serialVersionUID = 4420736202747927268L;

  /**
   * Default constructor. 
   */
  public AuthenticationFailedException() {
  }

  /**
   * @param message
   */
  public AuthenticationFailedException(String message) {
    super(message);
  }

  /**
   * @param cause
   */
  public AuthenticationFailedException(Throwable cause) {
    super(cause);
  }

  /**
   * @param message
   * @param cause
   */
  public AuthenticationFailedException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message
   * @param cause
   * @param enableSuppression
   * @param writableStackTrace
   */
  public AuthenticationFailedException(String message, Throwable cause,
      boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

}
