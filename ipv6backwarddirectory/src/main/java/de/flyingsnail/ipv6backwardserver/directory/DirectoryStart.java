/*
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

package de.flyingsnail.ipv6backwardserver.directory;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import javax.net.ServerSocketFactory;
import javax.persistence.EntityManager;
import javax.persistence.Persistence;
import javax.persistence.Query;
import javax.persistence.criteria.CriteriaBuilder;

/**
 * This creates the server sockets to recieve directory requests and the working 
 * thread pool to work on them.
 * 
 * @author pelzi
 *
 */
public class DirectoryStart implements DirectoryData {

  private int port;
  private int backlog;
  private InetAddress bindAddress = null;
  private static Logger log = Logger.getLogger(DirectoryStart.class.getName());
  
  ExecutorService execService;
  
  // persistence-related handlers
  private final EntityManager entityManager;
  private final CriteriaBuilder criteriaBuilder;
  

  /**
   * @param args
   */
  public static void main(String[] args) {
    try {
      InputStream configIS = ClassLoader.getSystemResourceAsStream("logging.properties");
      if (configIS != null)
        LogManager.getLogManager().readConfiguration(configIS);
      else
        log.log(Level.WARNING, "No logging properties found");
      
      Properties config = new Properties();
      config.load(DirectoryStart.class.getResourceAsStream("config.properties"));
      String ip = config.getProperty("ip");
      if (ip == null || "".equals(ip))
        throw new IllegalStateException("No IP configured");
      String port = config.getProperty("port");
      if (port == null || "".equals(port))
        throw new IllegalStateException ("No port configured");

      DirectoryStart tac = new DirectoryStart(Integer.valueOf(port), 10, (Inet4Address)Inet4Address.getByName(ip));
      tac.run();
    } catch (Throwable t) {
      log.log(Level.SEVERE, "Uncaught exception or error in main method. Server aborting", t);
    }
  }


  /**
   * @param port
   * @param backlog
   * @param bindAddress
   */
  public DirectoryStart(int port, int backlog, InetAddress bindAddress) {
    super();
    log.info("Creating DirectoryStart object");
    this.port = port;
    this.backlog = backlog;
    this.bindAddress = bindAddress;
    this.execService = Executors.newFixedThreadPool(10);
    this.entityManager = Persistence.createEntityManagerFactory("IPv6Directory").
        createEntityManager();
    this.criteriaBuilder = getEntityManager().getCriteriaBuilder();
    // a diagnostic query
    Query query = entityManager.createQuery("select count(u) from User u");
    Object res = query.getSingleResult();
    log.log(Level.INFO, "Users in database: {0}", res);
  }
  
  /**
   * Infinitely loop accepting on the server socket.
   */
  public void run() {
    try {
      ServerSocket serverSocket = ServerSocketFactory.getDefault().createServerSocket(port, backlog , bindAddress);
      log.log(Level.INFO, "Directory server is accepting connections on " + bindAddress + ":" + port);
      while (!serverSocket.isClosed()) {
        Socket socket = serverSocket.accept();
        log.log(Level.INFO, "Directory server connection received");
        socket.setSoLinger(true, 1); //wait max. 1 Second for Socket to close gracefully
        socket.setSoTimeout(5000); // wait max. 5 Seconds for receiving data from the socket
        DirectoryQueryHandler dqh = new DirectoryQueryHandler (socket, this);
        execService.submit(dqh);
      }
    } catch (IOException e) {
      log.log(Level.SEVERE, "Startup of directory server failed", e);
    } finally {
      log.info("Finished main accept loop");
    }

  }

  /* (non-Javadoc)
   * @see de.flyingsnail.ipv6backwardserver.directory.DirectoryData#getCriteriaBuilder()
   */
  @Override
  public CriteriaBuilder getCriteriaBuilder() {
    return criteriaBuilder;
  }


  /* (non-Javadoc)
   * @see de.flyingsnail.ipv6backwardserver.directory.DirectoryData#getEntityManager()
   */
  @Override
  public EntityManager getEntityManager() {
    return entityManager;
  }
  
}
