package de.flyingsnail.ipv6server.dtlstransporter;

import java.net.Inet6Address;
import java.rmi.NoSuchObjectException;
import java.util.Objects;

import org.bouncycastle.tls.DTLSTransport;
import org.eclipse.jdt.annotation.NonNull;

public interface DTLSData {
  public class ServerTransportTupel {
    private DTLSTransport transport;
    private IPv6DTlsServer server;
    /**
     * @param transport
     * @param server
     */
    public ServerTransportTupel(@NonNull IPv6DTlsServer server, @NonNull DTLSTransport transport) {
      super();
      this.transport = Objects.requireNonNull(transport);
      this.server = Objects.requireNonNull(server);
    }
    /**
     * @return the transport
     */
    public @NonNull DTLSTransport getTransport() {
      return transport;
    }
    /**
     * @return the server
     */
    public @NonNull IPv6DTlsServer getServer() {
      return server;
    }
    
  }

  /**
   * Retrieve the ServerTransportTupel object with the given IPv6 address.
   * @param sender the Inet6Address to get a server for
   * @return the DTLSTransport handling sender
   * @throws NoSuchObjectException in case no server is available for that address
   */
  @NonNull ServerTransportTupel getServerTransport(@NonNull Inet6Address sender)
      throws NoSuchObjectException;

  
  /**
   * Register an established DTLS session with the corresponding IPv6Address
   * @param sender the Inet6Address of the corresponding IPv6 address of this client
   * @param dtlsServer the IPv6DtlsServer that is controlling the connection of this client
   * @param dtls the DTLSTransport representing the connection.
   */
  void putServerAndTransport(@NonNull Inet6Address sender, @NonNull IPv6DTlsServer dtlsServer, @NonNull DTLSTransport dtls);
  
  /**
   * Remove an DTLS session from the registry (probably after the session ended).
   * @param sender the Inet6Address identifying the client.
   * @return the ServerTransportTupel that was removed
   */
  ServerTransportTupel removeServerTransport(@NonNull Inet6Address sender);
 
  
  /**
   * Retrieve all DTLSTransport instances available on this machine.
   * @return an Iterator over all instances.
   */
  Iterable<ServerTransportTupel> getAll();
  
}