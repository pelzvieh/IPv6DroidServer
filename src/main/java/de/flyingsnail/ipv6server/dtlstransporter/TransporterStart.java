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
import java.rmi.NoSuchObjectException;
import java.security.Security;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jdt.annotation.NonNull;

import sun.misc.Signal;


/**
 * @author pelzi
 *
 */
public class TransporterStart implements DTLSData {
  
  private static final String SOURCE_TUNTOPIPE = "tuntopipe";

  private static final String SOURCE_STDIN = "stdin";

  public static final long RE_READ_TUNNELS_MIN_INTERVAL_MILLIS = 300000l;

  /** Default period in which a cleaner thread checks for expired tunnels, in Milliseconds. */
  public static final long CLEANER_PERIOD = 5l * 1000l * 60l;

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
    
  /** Regitry of IPv6 addresses towards DTLS sessions */
  private HashMap<Inet6Address, DTLSTransport> dtlsHash;

  private DTLSListener dtlsListener;

  
  private static Logger logger = Logger.getLogger(TransporterStart.class.getName());

  private static Boolean passThrough;
  
  enum Source { TUNTOPIPE, FILEDESC };
  
  private static Source source;
  
  private static File input = null;
  private static File output = null;



  /**
   * @param args the command line arguments
   */
  public static void main(String[] args) {
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
        logger.log(Level.INFO, "Bundled logging configuration read");
      } catch (FileNotFoundException e) {
        logger.info("No extracted logging configuration found");
      }

      readStaticConfigurationItems();
      
      // if in pipe mode, read channels from args
      if (source == Source.FILEDESC) {
        if (args.length != 2) {
          System.err.println("Syntax: TransporterStart /dev/fd/[input fd] /dev/fd/[output fd]");
          System.exit(1);
        }
        input = new File(args[0]);
        if (!input.canRead()) {
          System.err.println("Cannot read from " + args[0]);
          System.exit(2);
        }
        output = new File (args[1]);
        if (!output.canWrite()) {
          System.err.println("Cannot write to " + args[1]);
          System.exit(3);
        }
      }
      
      // register BouncyCastle provider
      Security.addProvider(new BouncyCastleProvider());
      System.setProperty("org.bouncycastle.x509.enableCRLDP", "true");

      // construct our instance      
      TransporterStart ts = new TransporterStart();
      
      // Setup signal handler for USR2 to print summary of tunnels to logfile on kill -USR1
      Signal.handle(new Signal("USR2"), (Signal sig) ->
        {
          logger.log(Level.INFO, "Catched signal USR2, printing tunnel info");
          long count = ts.activeTunnelCount();
          logger.log(Level.INFO, "Connected tunnels count: " + count);
          ts.dtlsHash.forEach((Inet6Address ipv6, DTLSTransport server) 
              -> logger.log(Level.INFO, 
                            String.format(" %s <-> %s", server.toString(), ipv6.toString())
                  )
              );
        }
      );
      
      // provoke check of certificate chain by constructing an otherwise unused server instance
      final IPv6DTlsServer server = new IPv6DTlsServer(1000);
      logger.finer(()->"Construction of test IPv6DTlsServer succeeded: " + server);
      
      // now run until something terminal happens
      int exitCode = ts.run();
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
    
    String passThroughFlag = config.getProperty("passthrough", "true");
    passThrough = Boolean.valueOf(passThroughFlag);
    logger.config(()-> passThrough ? "pass through" : "no pass through");
    
    String sourceString = config.getProperty("source", SOURCE_TUNTOPIPE);
    switch (sourceString) {
      case SOURCE_TUNTOPIPE:
        source = Source.TUNTOPIPE;
        break;
      case SOURCE_STDIN:
        source = Source.FILEDESC;
        break;
      default:
        throw new IllegalStateException ("No such source available: " + sourceString);
        
    }
  }

  /**
   * Constructor.
   * @throws IOException in case of network problems
   */
  public TransporterStart() throws IOException  {
    super();
    this.dtlsHash = new HashMap<>();

    TransporterParams params = new TransporterParams();
    params.heartbeat = 10*60*1000;
    params.ipv4Pop = (Inet4Address) ipv4SocketAddress.getAddress();
    params.portPop = ipv4SocketAddress.getPort();
    params.mtu = 1300;
    dtlsListener = new DTLSListener(params);
    logger.info(() -> "TransporterStart constructed for " + params.ipv4Pop + ":" + params.portPop);
  }

  /**
   * Run the copying process
   */
  private int run() {
    IPv6InputHandler ipv6InputHandler = (source == Source.TUNTOPIPE) ? 
        new IPv6InputHandler(this, "tun0", passThrough) :
        new IPv6InputHandler(this, input, output, passThrough);
    logger.info("IPv6InputHandler is constructed");

    Thread ip4Thread = new Thread(new IPv4InputHandler(this, dtlsListener, ipv6InputHandler), "IPv4 consumer");
    Thread ip6Thread = new Thread(ipv6InputHandler, "IPv6 consumer");
    ip4Thread.setDaemon(true);
    ip6Thread.setDaemon(true);
    ip4Thread.start();
    ip6Thread.start();

    logger.info("Startup completed, threads running");
    monitorThreads (new Thread[] {ip4Thread, ip6Thread});
    logger.warning("Thread monitor ended, will terminate");
    return EXIT_NORMAL;
  }

  private void monitorThreads(Thread[] threads) {
    while (true)
      for (Thread thread: threads) {
        try {
          thread.join(10000);
        } catch (InterruptedException e) {
          logger.log(Level.SEVERE, "Interrupt in main thread");
          Thread.currentThread().interrupt();
          return;
        }
        if (!thread.isAlive()) {
          throw new IllegalStateException (String.format("Thread %s has died, will terminate", thread.getName()));
        }
      }
  }


  /* (non-Javadoc)
   * @see de.flyingsnail.ipv6backwardserver.transporter.AyiyaData#getServer(java.net.Inet6Address)
   */
  @Override
  public DTLSTransport getServer(@NonNull Inet6Address sender) throws NoSuchObjectException {
    DTLSTransport matching = dtlsHash.get(sender);
    if (matching == null)
      throw new NoSuchObjectException("No DTLSTransport object for address " + sender);
    return matching;
  }
  
  public long activeTunnelCount () {
    return dtlsHash.size();
  }

  @Override
  public Iterable<DTLSTransport> getAll() {
    return dtlsHash.values();
  }

  @Override
  public void putServer(@NonNull Inet6Address sender, @NonNull DTLSTransport dtls) {
    dtlsHash.put(sender, dtls);
  }

  @Override
  public DTLSTransport removeServer(@NonNull Inet6Address sender) {
    return dtlsHash.remove(sender);
  }
}
