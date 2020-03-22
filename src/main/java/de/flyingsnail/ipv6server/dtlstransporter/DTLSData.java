package de.flyingsnail.ipv6server.dtlstransporter;

import java.net.Inet6Address;
import java.rmi.NoSuchObjectException;

import org.bouncycastle.tls.DTLSTransport;
import org.eclipse.jdt.annotation.NonNull;

public interface DTLSData {

  /**
   * Retrieve the server object with the given IPv6 address.
   * @param sender the Inet6Address to get a server for
   * @return the DTLSTransport handling sender
   * @throws NoSuchObjectException in case no server is available for that address
   */
  DTLSTransport getServer(@NonNull Inet6Address sender)
      throws NoSuchObjectException;
  
  /**
   * Register an established DTLS session with the corresponding IPv6Address
   * @param sender the Inet6Address of the corresponding IPv6 address of this client
   * @param server the DTLSTransport representing the connection.
   */
  void putServer(@NonNull Inet6Address sender, @NonNull DTLSTransport dtls);
  
  /**
   * Remove an DTLS session from the registry (probably after the session ended).
   * @param sender the Inet6Address identifying the client.
   * @return 
   */
  DTLSTransport removeServer(@NonNull Inet6Address sender);
 
  
  /**
   * Retrieve all DTLSTransport instances available on this machine.
   * @return an Iterator over all instances.
   */
  Iterable<DTLSTransport> getAll();

}