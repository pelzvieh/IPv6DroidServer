package de.flyingsnail.ipv6backwardserver.transporter;

import java.net.Inet6Address;
import java.rmi.NoSuchObjectException;

import org.eclipse.jdt.annotation.NonNull;

import de.flyingsnail.ipv6backwarddata.ayiya.AyiyaServer;

public interface AyiyaData {

  @NonNull
  AyiyaServer getServer(@NonNull Inet6Address sender)
      throws NoSuchObjectException;

}