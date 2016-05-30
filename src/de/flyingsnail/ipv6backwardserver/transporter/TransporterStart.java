/**
 * Copyright (c) 2016 Dr. Andreas Feldner.
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

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.rmi.NoSuchObjectException;
import java.util.HashMap;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.jdt.annotation.NonNull;

import de.flyingsnail.ipv6droid.ayiya.AyiyaServer;
import de.flyingsnail.ipv6droid.ayiya.ConnectionFailedException;
import de.flyingsnail.ipv6droid.ayiya.TicTunnel;


/**
 * @author pelzi
 *
 */
public class TransporterStart implements AyiyaData {
  private Inet4Address ipv4pop;
  private int ipv4port;
  private DatagramChannel ipv4Channel;
  private Set<TicTunnel> tunnels;
  private HashMap<Inet6Address, AyiyaServer> ayiyaHash;
  
  private static Logger logger = Logger.getLogger(TransporterStart.class.getName());

  /**
   * @param args
   */
  public static void main(String[] args) {
    try {
      Properties config = new Properties();
      config.load(TransporterStart.class.getResourceAsStream("config.properties"));
      String ip = config.getProperty("ip");
      if (ip == null || "".equals(ip))
        throw new IllegalStateException("No IP configured");
      String port = config.getProperty("port");
      if (port == null || "".equals(port))
        throw new IllegalStateException ("No port configured");
      TransporterStart ts = new TransporterStart((Inet4Address)Inet4Address.getByName(ip), Integer.valueOf(port));
      ts.run();
    } catch (Throwable t) {
      logger.log(Level.SEVERE, "Uncaught error in main, server process is aborting", t);
    }
  }

  /**
   * @param ipv4pop the Inet4Address to bind to as incoming endpoint
   * @param ipv4port the int giving the port number to listen to for incoming packets.
   */
  public TransporterStart(Inet4Address ipv4pop, int ipv4port)  {
    super();
    this.ipv4pop = ipv4pop;
    this.ipv4port = ipv4port;
  }

  /**
   * Run the copying process
   */
  private void run() {
    try {
      ipv4Channel = DatagramChannel.open();
      ipv4Channel.bind(new InetSocketAddress(ipv4pop, ipv4port));
      logger.info("Listening for udp packets on " + ipv4pop + ":" + ipv4port);

      readTunnelSet();
      IPv6InputHandler ipv6InputHandler = new IPv6InputHandler(this, "tun0");
      Thread ip4Thread = new Thread(new IPv4InputHandler(this, ipv4Channel, ipv6InputHandler), "IPv4 consumer");
      Thread ip6Thread = new Thread(ipv6InputHandler, "IPv6 consumer");
      ip4Thread.setDaemon(false);
      ip6Thread.setDaemon(false);
      ip4Thread.start();
      ip6Thread.start();
      
    } catch (IOException e) {
      logger.log(Level.WARNING, "IOException caught in transporter", e);
    }
  }

  private void readTunnelSet() throws IOException {
    Properties config = new Properties();
    config.load(TransporterStart.class.getResourceAsStream("/de/flyingsnail/ipv6backwardserver/tunnel.properties"));
    TicTunnel tunnel = new TicTunnel(config.getProperty("TunnelId"));

    tunnel.setType (config.getProperty("Type"));
    tunnel.setIpv6Endpoint (config.getProperty("IPv6Endpoint"));
    tunnel.setIpv6Pop (config.getProperty("IPv6PoP"));
    tunnel.setPrefixLength (Integer.valueOf(config.getProperty("IPv6PrefixLength")));
    tunnel.setPopName (config.getProperty("PoPName"));
    tunnel.setIPv4Pop (ipv4pop.toString());
    tunnel.setUserState (config.getProperty("UserState"));
    tunnel.setAdminState (config.getProperty("AdminState"));
    tunnel.setPassword (config.getProperty("Password"));
    tunnel.setHeartbeatInterval (Integer.valueOf(config.getProperty("HeartbeatInterval")));
    tunnel.setMtu (Integer.valueOf(config.getProperty("TunnelMTU")));
    tunnel.setTunnelName (config.getProperty("TunnelName"));
    
    tunnels.clear();
    tunnels.add(tunnel);
    
    for (TicTunnel t: tunnels) {
      try {
        ayiyaHash.put(t.getIpv6Endpoint(), new AyiyaServer(t, ipv4Channel));
      } catch (ConnectionFailedException e) {
        logger.log(Level.WARNING, "Could not create AyiyaServer for configured tunnel", e);
      }
    }
  }

  /* (non-Javadoc)
   * @see de.flyingsnail.ipv6backwardserver.transporter.AyiyaData#getServer(java.net.Inet6Address)
   */
  @Override
  public @NonNull AyiyaServer getServer(@NonNull Inet6Address sender) throws NoSuchObjectException {
    AyiyaServer matching = ayiyaHash.get(sender);
    if (matching == null)
      throw new NoSuchObjectException(sender.toString());
    return matching;
  }

}
