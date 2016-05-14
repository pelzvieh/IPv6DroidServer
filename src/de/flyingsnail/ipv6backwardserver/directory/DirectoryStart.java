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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ServerSocketFactory;

/**
 * This creates the server sockets to recieve directory requests and the working 
 * thread pool to work on them.
 * 
 * @author pelzi
 *
 */
public class DirectoryStart {

  private int port;
  private int backlog;
  private InetAddress bindAddress = null;
  private static Logger log = Logger.getLogger(DirectoryStart.class.getName());
  
  ExecutorService execService;
  
  

  /**
   * @param args
   */
  public static void main(String[] args) {
    try {
      DirectoryStart tac = new DirectoryStart(3874, 10, null);
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
    this.port = port;
    this.backlog = backlog;
    this.bindAddress = bindAddress;
    this.execService = Executors.newFixedThreadPool(10);
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
        DirectoryQueryHandler dqh = new DirectoryQueryHandler (socket);
        execService.submit(dqh);
      }
    } catch (IOException e) {
      log.log(Level.SEVERE, "Startup of directory server failed", e);
    } finally {
      log.info("Finished main accept loop");
    }

  }

}
