/**
 * Copyright (c) 2023 Dr. Andreas Feldner (pelzi).
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

import java.security.Permission;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A SecurityManager that turns attempts to System.exit from within
 * libraries into SecurityExceptions. This should not be required,
 * but there was some indication that some BouncyCastle algorithms
 * call System.exit on unexpected circumstances.
 * @todo reproduce the problem and open problem report upstream
 * @author pelzi
 *
 */
class MySecurityManager extends SecurityManager {
  private static Logger logger = Logger.getLogger(MySecurityManager.class.getName());

  @Override public void checkExit(int status) {
    SecurityException exception = new SecurityException();
    StackTraceElement[] callStack = exception.getStackTrace();
    if (callStack.length < 2 || !callStack[callStack.length - 2].getClassName().equals("java.lang.System")) {
      // we only want System.exit to be called directly from the main method
      logger.log(Level.WARNING, "Attempt to invoke System.exit with status " + status + " - throwing following exception:", exception);
      throw exception;
    }
  }

  @Override public void checkPermission(Permission perm) {
      // Allow other activities by default
  }
}
