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
package de.flyingsnail.ipv6server.dtlstransporter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.rmi.NoSuchObjectException;
import java.security.Security;
import java.util.HashMap;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.DTLSTransport;
import org.eclipse.jdt.annotation.NonNull;

import sun.misc.Signal;


/**
 * @author pelzi
 *
 */
public class TransporterStart implements DTLSData {
  
  /** Exit code on normal completion */
  private static final int EXIT_NORMAL = 0;

  /** Exit code on fatal misconfiguration */
  private static final int EXIT_CONFIG_ERR = 1;

  /** Exit code on fatal io errors */
  private static final int EXIT_IO_ERR = 2;
  
  /** Exit code on unknown termination */
  private static final int EXIT_UNKNOWN = 4;

  // Configuration stuff
  
  /** Global configuration options */
  private static Properties config = new Properties();

  /** My IPv4 socket address (i.e. IP and port) */
  private static InetSocketAddress ipv4SocketAddress;

  /** 
   * Maximum delay between two checks for sessions with 
   * expired certificates in milliseconds 
   * */
  private static Long expiryPeriod;

  /** Regitry of IPv6 addresses towards DTLS sessions */
  private HashMap<Inet6Address, ServerTransportTupel> dtlsHash;

  private DTLSListener dtlsListener;

  private WritableByteChannel toAyiya;
  
  private ReadableByteChannel fromAyiya;

  
  private static Logger logger = Logger.getLogger(TransporterStart.class.getName());

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args) {
    Path input = null;
    Path output = null;
    boolean passThrough;

    if (args.length == 2) {
      passThrough = true;
      String in = args[0];
      String out = args[1];
      input = Path.of(in);
      output = Path.of(out);
      if (!input.toFile().exists()) {
        System.err.println (String.format("File %s not found", in));
        System.exit(EXIT_IO_ERR);
      }
      if (!output.toFile().exists()) {
        System.err.println (String.format("File %s not found", out));
        System.exit(EXIT_IO_ERR);
      }
      
    } else if (args.length == 0) {
      passThrough = false;
    } else { // invalid number of arguments
      passThrough = false;
      String myJar;
      try {
        myJar = TransporterStart.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
      } catch (Exception e) {
        Logger.getAnonymousLogger().log(Level.WARNING, "Could not determine name of executable jar for user help", e);
        myJar = "<executable jar file>";
      }
      System.err.println(String.format("Syntax: %s [<named pipe for input> <named pipe for output>]", myJar));
      System.exit(EXIT_CONFIG_ERR);
    }

    
    try {
      InputStream loggingConfigIS = ClassLoader.getSystemResourceAsStream("logging.properties");
      if (loggingConfigIS != null) {
        LogManager.getLogManager().readConfiguration(loggingConfigIS);
        logger.log(Level.INFO, "Bundled logging configuration read");
      } else
        logger.log(Level.WARNING, "No logging properties found");
      
      try {
        // try to read a separate configuration file, if it exists
        loggingConfigIS = new FileInputStream(new File("logging_dtls.properties"));
        LogManager.getLogManager().readConfiguration(loggingConfigIS);
        logger.log(Level.INFO, "Detached logging configuration read");
        logger.log(Level.FINEST, "Logger is logging extreme verbose");
      } catch (FileNotFoundException e) {
        logger.info("No extracted logging configuration found");
      }

      readStaticConfigurationItems();
      
      // register BouncyCastle provider
      Security.addProvider(new BouncyCastleProvider());
      System.setProperty("org.bouncycastle.x509.enableCRLDP", "true");

      // construct our instance      
      TransporterStart ts = passThrough ? new TransporterStart() : new TransporterStart(input, output);
      
      // Setup signal handler for USR2 to print summary of tunnels to logfile on kill -USR1
      Signal.handle(new Signal("USR2"), (Signal sig) ->
        {
          logger.log(Level.INFO, "Catched signal USR2, printing tunnel info");
          long count = ts.activeTunnelCount();
          logger.log(Level.INFO, "Connected tunnels count: " + count);
          ts.dtlsHash.forEach((Inet6Address ipv6, ServerTransportTupel serverTransport) 
              -> logger.log(Level.INFO, 
                            String.format(" %s <-> %s", serverTransport.getTransport().toString(), ipv6.toString())
                  )
              );
        }
      );
      
      // provoke check of certificate chain by constructing an otherwise unused server instance
      //MySecurityManager secManager = new MySecurityManager();
      //System.setSecurityManager(secManager);
      logger.finest("Trying to construct an IPv6DTlsServer");
      final IPv6DTlsServer server = new IPv6DTlsServer(1000);
      logger.finer(()->"Construction of IPv6DTlsServer succeeded: " + server);
      
      // now run until something terminal happens
      int exitCode = ts.run();
      logger.info("Transport server main loop exited with result " + exitCode);
      System.exit(exitCode);
    } catch (IllegalStateException ise) {
      logger.log(Level.SEVERE, "Unrecoverable configuration error", ise);
      System.exit(EXIT_CONFIG_ERR);
    } catch (IOException ioe) {
      logger.log(Level.SEVERE, "IO error preventing startup", ioe);
      System.exit(EXIT_IO_ERR);
    } catch (Throwable t) {
      logger.log(Level.SEVERE, "Uncaught error in main, server process is aborting", t);
      System.exit(EXIT_UNKNOWN);
    }
  }

  /**
   * Initialize config properties
   * @throws IOException
   * @throws IllegalStateException
   */
  static void readStaticConfigurationItems() throws IOException, IllegalStateException {
    config = new Properties();
    InputStream localConfigIS = ClassLoader.getSystemResourceAsStream("config.properties");
    if (localConfigIS == null) {
      throw new IllegalStateException ("config.properties is missing, terminating");
    }
    config.load(localConfigIS);
    
    // read out startup config entries
    String ip = config.getProperty("ip");
    if (ip == null || "".equals(ip))
      throw new IllegalStateException("No IP configured");
    
    String port = config.getProperty("port");
    if (port == null || "".equals(port))
      throw new IllegalStateException ("No port configured");
    
    ipv4SocketAddress = new InetSocketAddress (ip, Integer.valueOf(port));
    logger.config(() -> "bind address: " + ipv4SocketAddress);

    String expiryPeriodString = config.getProperty("expiry_period_ms");
    if (expiryPeriodString == null || "".equals(expiryPeriodString))
      throw new IllegalStateException ("No expiryPeriod configured");
    expiryPeriod = Long.valueOf(expiryPeriodString);
  }

  /**
   * Constructor. Transporter without delegation to other protocol.
   * @throws IOException in case of communication problems.
   */
  public TransporterStart() throws IOException {
    super();
    this.dtlsHash = new HashMap<>();
    // close all active sessions if the vm shuts down
    Runtime.getRuntime().addShutdownHook(new Thread(()->exitHandler()));

    TransporterParams params = new TransporterParams();
    params.heartbeat = 10*60*1000;
    params.ipv4Pop = (Inet4Address) ipv4SocketAddress.getAddress();
    params.portPop = ipv4SocketAddress.getPort();
    params.mtu = 1300;
    dtlsListener = new DTLSListener(params);
  }

  /**
   * Constructor for a transporter with delegation to another protocol.
   * @param output the path of a named pipe to write ipv6 packets to, that are not handled by this transporter.
   * @param input  the path of a named pipe to read additional ipv6 packets from.
   * @throws IOException in case of network problems
   */
  public TransporterStart(Path input, Path output) throws IOException  {
    this();
    toAyiya = FileChannel.open(output, Set.of(StandardOpenOption.APPEND, StandardOpenOption.WRITE));
    fromAyiya = FileChannel.open(input, Set.of(StandardOpenOption.READ));
  }

  /**
   * Run the copying process. It will continue to run as long as all required
   * components are in orderly state.
   * @return a Unix return value, i.e. 0 for success.
   */
  private int run() {
    IPv6InputHandler ipv6InputHandler;
    try {
      ipv6InputHandler = new IPv6InputHandler(this, "tun0", toAyiya);
    } catch (IllegalStateException | IOException e) {
      logger.log(Level.SEVERE, "Could not start IPv6InputHandler", e);
      return EXIT_IO_ERR;
    }
    logger.info("IPv6InputHandler is constructed");

    Thread ip4Thread = new Thread(new IPv4InputHandler(this, dtlsListener, ipv6InputHandler, expiryPeriod), "IPv4 consumer");
    Thread ip6Thread = new Thread(ipv6InputHandler, "IPv6 consumer");
    ip4Thread.setDaemon(true);
    ip6Thread.setDaemon(true);
    ip4Thread.start();
    ip6Thread.start();
    
    Thread ip6InThread = null;
    if (fromAyiya != null) {
      ip6InThread = new Thread(new Runnable() {
        public void run() {
          ByteBuffer packet = ByteBuffer.allocateDirect(32767);
          try { 
            while (fromAyiya.isOpen()) {
              packet.clear();
              fromAyiya.read(packet);
              packet.flip();
              ipv6InputHandler.write(packet);
            }
          } catch (IOException e) {
            logger.log(Level.SEVERE, "Back-Pipe from ayiya transporter broken", e);
          }
        }
      }, "IPv6BackPassThread");
      ip6InThread.setDaemon(true);
      ip6InThread.start();
    }

    logger.info("Startup completed, threads running");
    monitorThreads (
        (fromAyiya != null) ?
          new Thread[] {ip4Thread, ip6Thread, ip6InThread}
        : new Thread[] {ip4Thread, ip6Thread}
        );
    logger.warning("Thread monitor ended, will terminate");
    return EXIT_NORMAL;
  }

  /**
   * Wait as long as one of the supplied threads ends. This method returning means
   * that at least one of the supplied threads has ceased.
   * @param threads an Array of Thread objects that are expected to run for orderly operations.
   */
  private void monitorThreads(Thread[] threads) {
    while (true)
      for (Thread thread: threads) {
        logger.fine(() -> "Joining on thread " + thread.getName());

        try {
          thread.join(10000);
        } catch (InterruptedException e) {
          logger.log(Level.SEVERE, "Interrupt in main thread");
          exitHandler();
          Thread.currentThread().interrupt();
          return;
        }
        if (!thread.isAlive()) {
          throw new IllegalStateException (String.format("Thread %s has died, will terminate", thread.getName()));
        }
        logger.fine(() -> thread.getName() + " is alive");
      }
  }


  /**
   * Before JVM shutdown: Close all active sessions.
   */
  private void exitHandler() {
    logger.info("Exit handler activated, closing all sessions");
    for (ServerTransportTupel serverTransport: getAll()) {
      try {
        serverTransport.getTransport().close();
      } catch (Exception e) {
        logger.warning(() -> "Shutting down session " + serverTransport.getTransport() + " failed.");
      }
    }
    dtlsHash.clear();
  }

  /* (non-Javadoc)
   * @see de.flyingsnail.ipv6backwardserver.transporter.AyiyaData#getServer(java.net.Inet6Address)
   */
  @Override
  public @NonNull ServerTransportTupel getServerTransport(@NonNull Inet6Address sender) throws NoSuchObjectException {
    ServerTransportTupel matching = dtlsHash.get(sender);
    if (matching == null)
      throw new NoSuchObjectException("No DTLSTransport object for address " + sender);
    return matching;
  }
  
  public long activeTunnelCount () {
    return dtlsHash.size();
  }

  @Override
  public Iterable<ServerTransportTupel> getAll() {
    return dtlsHash.values();
  }

  @Override
  public void putServerAndTransport(@NonNull Inet6Address sender, @NonNull IPv6DTlsServer server, @NonNull DTLSTransport dtls) {
    dtlsHash.put(sender, new ServerTransportTupel(server, dtls));
  }

  @Override
  public ServerTransportTupel removeServerTransport(@NonNull Inet6Address sender) {
    return dtlsHash.remove(sender);
  }
}
