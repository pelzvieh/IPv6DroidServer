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
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.rmi.NoSuchObjectException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import javax.persistence.EntityManager;
import javax.persistence.Persistence;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;

import sun.misc.Signal;
import sun.misc.SignalHandler;

import org.eclipse.jdt.annotation.NonNull;

import de.flyingsnail.ipv6backwarddata.ayiya.AyiyaServer;
import de.flyingsnail.ipv6backwarddata.ayiya.ConnectionFailedException;
import de.flyingsnail.ipv6backwarddata.ayiya.TicTunnel;


/**
 * @author pelzi
 *
 */
public class TransporterStart implements AyiyaData {
  private Inet4Address ipv4pop;
  private int ipv4port;
  private DatagramChannel ipv4Channel;
  private List<TicTunnel> tunnels;
  private HashMap<Inet6Address, AyiyaServer> ayiyaHash;
  
  private static Logger logger = Logger.getLogger(TransporterStart.class.getName());

  /**
   * @param args
   */
  @SuppressWarnings("restriction")
  public static void main(String[] args) {
    try {
      InputStream configIS = ClassLoader.getSystemResourceAsStream("logging.properties");
      if (configIS != null)
        LogManager.getLogManager().readConfiguration(configIS);
      else
        logger.log(Level.WARNING, "No logging properties found");

      Properties config = new Properties();
      config.load(TransporterStart.class.getResourceAsStream("config.properties"));
      String ip = config.getProperty("ip");
      if (ip == null || "".equals(ip))
        throw new IllegalStateException("No IP configured");
      String port = config.getProperty("port");
      if (port == null || "".equals(port))
        throw new IllegalStateException ("No port configured");
      TransporterStart ts = new TransporterStart((Inet4Address)Inet4Address.getByName(ip), Integer.valueOf(port));
      // Setup signal handler for SIGHUP to reload tunnels on kill -HUP
      Signal.handle(new Signal("HUP"), new SignalHandler () {
        public void handle(Signal sig) {
          try {
            logger.log(Level.INFO, "Catched signal sigup, re-reading tunnel list");
            ts.readTunnelSet();
          } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to re-read tunnel list", e);
          }
        }
      });
      ts.run();
    } catch (Throwable t) {
      logger.log(Level.SEVERE, "Uncaught error in main, server process is aborting", t);
      System.exit(1);
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
    this.tunnels = new ArrayList<TicTunnel>(0);
    this.ayiyaHash = new HashMap<Inet6Address, AyiyaServer>();
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
      ip4Thread.setDaemon(true);
      ip6Thread.setDaemon(true);
      ip4Thread.start();
      ip6Thread.start();
      monitorThreads (new Thread[] {ip4Thread, ip6Thread});
    } catch (IOException e) {
      logger.log(Level.WARNING, "IOException caught in transporter", e);
    }
  }

  private void monitorThreads(Thread[] threads) {
    while (true)
      for (Thread thread: threads) {
        try {
          thread.join(10000);
        } catch (InterruptedException e) {
          logger.log(Level.SEVERE, "Interrupt in main thread");
          System.exit(2);
        }
        if (!thread.isAlive()) {
          logger.log(Level.SEVERE, "Thread {0} has died, will terminate", thread.getName());
          System.exit(3);
        }
      }
  }

  private void readTunnelSet() throws IOException {
    EntityManager entityManager = Persistence.createEntityManagerFactory("IPv6Directory").
        createEntityManager();
    CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
    
    // query all tunnels
    CriteriaQuery<TicTunnel> criteriaQuery = criteriaBuilder.createQuery(TicTunnel.class);
    Root<TicTunnel> ticTunnelRoot = criteriaQuery.from(TicTunnel.class);
    criteriaQuery.select(ticTunnelRoot);
    TypedQuery<TicTunnel> query = entityManager.createQuery(criteriaQuery);
    tunnels.clear();
    tunnels = query.getResultList();
    logger.log(Level.INFO, "Read {0} tunnel definitions", tunnels.size());
    
    ayiyaHash.clear();
    for (TicTunnel t: tunnels) {
      // the tunnel property IPv4Pop is not persisted, but bound dynamically to our listening socket
      t.setIPv4Pop(ipv4pop.getHostAddress());
      try {
        logger.log(Level.INFO, "adding Ayiya instance for tunnel {0}", t);
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
