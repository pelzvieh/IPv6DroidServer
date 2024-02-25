/**
 * Copyright (c) 2020 Dr. Andreas Feldner (pelzi).
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

import java.io.IOException;
import java.nio.file.Path;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.flyingsnail.ipv6server.dtlstransporter.DTLSData.ServerTransportTupel;

/**
 * @author pelzi
 *
 */
public class DTLSTransporterStartTest {

  private TransporterStart transporterStart;
  
  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
    TransporterStart.readStaticConfigurationItems();
    transporterStart = new TransporterStart(Path.of("/dev/null"), Path.of("/dev/null"));
  }

  /**
   * @throws java.lang.Exception
   */
  @After
  public void tearDown() throws Exception {
  }

  @Test
  public void testGetAll() throws IOException {
    Iterable<ServerTransportTupel> sessions = transporterStart.getAll();
    for (ServerTransportTupel session: sessions) {
      System.out.println("- " + session.getTransport().toString());
    }
  }
}
