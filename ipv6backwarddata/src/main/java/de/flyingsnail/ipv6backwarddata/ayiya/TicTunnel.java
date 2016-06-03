package de.flyingsnail.ipv6backwarddata.ayiya;
/*
 * Copyright (c) 2013-2016 Dr. Andreas Feldner.
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU Lesser General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU Lesser General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Contact information and current version at http://www.flying-snail.de/IPv6Droid
 */



import java.io.Serializable;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.Date;

import javax.persistence.Cacheable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import org.eclipse.persistence.annotations.Convert;
import org.eclipse.persistence.annotations.ObjectTypeConverter;

/**
 * This represents the tunnel description as delivered by the tic protocol.
 * Created by pelzi on 17.08.13.
 */
@Entity
@Cacheable
public class TicTunnel implements Serializable {
  private static final long serialVersionUID = 7828811405806439946L;

  /** the id to use in tic queries */
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private String id;

  /**
   * The id told in the tunnel description. It is different in the examples given (no leading "T")
   * - no idea why we have two ids.
   */
  @Column(unique = true, nullable = false)
  private String tunnelId;

  /**
   * The type of tunnel. Ayiya is the only one expected here.
   */
  @Column(nullable = false, length = 10)
  private String type;

  /**
   * IPv6 endpoint of the tunnel
   */
  
  @Column(nullable = false, unique = true)
  private Inet6Address ipv6Endpoint;

  /**
   * IPv6 address of the POP.
   */
  @Column(nullable = false)
  private Inet6Address ipv6Pop;

  /**
   * Prefix length of the tunnel endpoint.
   */
  @Column(nullable = false, length = 3)
  private int prefixLength;

  /**
   * The name of the POP.
   */
  @Column(nullable = false)
  private String popName;

  /** 
   * POP address in IPv4. This is an attribute that arises from the installation, not persisted!
   */
  private Inet4Address ipv4Pop;

  /**
   * A String representing the state configured by the user.
   */
  @Column(nullable = false, length = 10)
  private String userState;

  /**
   * A String representing the state configured by the administrator.
   */
  @Column(nullable = false, length = 10)
  private String adminState;

  /**
   * A String with the connection password
   */
  @Column(nullable = false, length = 30)
  private String password;

  /**
   * The heartbeat interval in seconds.
   */
  @Column(nullable = false, length = 4)
  private int heartbeatInterval;

  public String getTunnelName() {
    return tunnelName;
  }

  public void setTunnelName(String tunnelName) {
    this.tunnelName = tunnelName;
  }

  /**
   * The user-given name of the tunnel.
   */
  @Column(nullable = false, length = 255)
  private String tunnelName;

  /** The maximum transmission unit in bytes. */
  @Column(length = 4, nullable = false)
  private int mtu;

  /** The timestamp of this tunnel's creation */
  @Column(nullable = false)
  private Date creationDate = new Date();

  /**
   * Default constructor. Required for JPA.
   */
  public TicTunnel() {
  }
  /**
   * Constructor. All attributes apart from id created null.
   * @param id a String representing the id to use for querying the tic.
   */
  public TicTunnel(String id) {
    this.id = id;
  }

  public Inet4Address getIPv4Pop() {
    return ipv4Pop;
  }

  public void setIPv4Pop(String ipv4Pop) throws UnknownHostException {
    this.ipv4Pop = (Inet4Address)Inet4Address.getByName (ipv4Pop);
  }

  public String getTunnelId() {
    return tunnelId;
  }

  public void setTunnelId(String tunnelId) {
    this.tunnelId = tunnelId;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public Inet6Address getIpv6Endpoint() {
    return ipv6Endpoint;
  }

  public void setIpv6Endpoint(String ipv6Endpoint) throws UnknownHostException {
    this.ipv6Endpoint = (Inet6Address)Inet6Address.getByName(ipv6Endpoint);
  }

  public Inet6Address getIpv6Pop() {
    return ipv6Pop;
  }

  public void setIpv6Pop(String ipv6Pop) throws UnknownHostException {
    this.ipv6Pop = (Inet6Address)Inet6Address.getByName(ipv6Pop);
  }

  public int getPrefixLength() {
    return prefixLength;
  }

  public void setPrefixLength(int prefixLength) {
    this.prefixLength = prefixLength;
  }

  public String getPopName() {
    return popName;
  }

  public void setPopName(String popName) {
    this.popName = popName;
  }

  public String getUserState() {
    return userState;
  }

  public void setUserState(String userState) {
    this.userState = userState;
  }

  public String getAdminState() {
    return adminState;
  }

  public void setAdminState(String adminState) {
    this.adminState = adminState;
  }

  /**
   * Is this tunnel enabled?
   * @return true if both user and admin enabled this tunnel.
   */
  public boolean isEnabled() {
    return "enabled".equals(getUserState()) && "enabled".equals(getAdminState());
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public int getHeartbeatInterval() {
    return heartbeatInterval;
  }

  public void setHeartbeatInterval(int heartbeatInterval) {
    this.heartbeatInterval = heartbeatInterval;
  }

  public int getMtu() {
    return mtu;
  }

  public void setMtu(int mtu) {
    this.mtu = mtu;
  }

  public boolean isValid() {
    return (mtu != 0) && (password != null) && (ipv4Pop != null) && (ipv6Pop != null);
  }

  public Date getCreationDate() {
    return creationDate;
  }



  /**
   * This is for Tic, really - it takes the keywords as given by the Tic protocol to describe
   * a tunnel set the respective properties.
   * @param key a String representing the key as of Tic tunnel query.
   * @param value a String representing the value.
   * @return true if we could identify the key and parse the value.
   */
  protected boolean parseKeyValue(String key, String value) {
    // we cannot use Java 7 switch on String, so implementation is no fun at all :-(
    try {
      if ("TunnelId".equalsIgnoreCase(key))
        setTunnelId(value);
      else if ("Type".equalsIgnoreCase(key))
        setType(value);
      else if ("IPv6 Endpoint".equalsIgnoreCase(key))
        setIpv6Endpoint(value);
      else if ("IPv6 PoP".equalsIgnoreCase(key))
        setIpv6Pop(value);
      else if ("IPv6 PrefixLength".equalsIgnoreCase(key))
        setPrefixLength(Integer.parseInt(value));
      else if ("PoP Name".equalsIgnoreCase(key) || "PoP Id".equalsIgnoreCase(key))
        setPopName(value);
      else if ("IPv4 PoP".equalsIgnoreCase(key))
        setIPv4Pop(value);
      else if ("UserState".equalsIgnoreCase(key))
        setUserState(value);
      else if ("AdminState".equalsIgnoreCase(key))
        setAdminState(value);
      else if ("Password".equalsIgnoreCase(key))
        setPassword(value);
      else if ("Heartbeat_Interval".equalsIgnoreCase(key))
        setHeartbeatInterval(Integer.parseInt(value));
      else if ("Tunnel MTU".equalsIgnoreCase(key))
        setMtu(Integer.parseInt(value));
      else if ("Tunnel Name".equalsIgnoreCase(key))
        setTunnelName(value);
      else
        return false;

      return true; // if we're here, some method call succeeded.
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("unable to resolve string intended to be an address: " + value, e);
    }
  }

  /**
   * Return if the two instances are from business logic the same. They are, if they have the same
   * ID.
   * @param o the object to compare this to
   * @return a boolean indicating equality
   */
  @Override
  public boolean equals(Object o) {
    return (o != null) && (o instanceof TicTunnel) && (((TicTunnel) o).getTunnelId().equals(this.tunnelId));
  }

  /**
   * Return if this TicTunnel has all the same settings as another TicTunnel. In contrast to equals(),
   * this would return false on a different version of the same tunnel.
   * @param o the object to compare this to
   * @return a boolean indicating equality of all attributes
   */
  public boolean equalsDeep(Object o) {
    return equals (o)
        && getHeartbeatInterval() == ((TicTunnel)o).getHeartbeatInterval()
        && getTunnelName().equals(((TicTunnel)o).getTunnelName())
        && getIPv4Pop().equals(((TicTunnel)o).getIPv4Pop())
        && getType().equals(((TicTunnel)o).getType())
        && getIpv6Endpoint().equals(((TicTunnel)o).getIpv6Endpoint())
        && getIpv6Pop().equals(((TicTunnel)o).getIpv6Pop())
        && getPrefixLength() == ((TicTunnel)o).getPrefixLength()
        && getPopName().equals(((TicTunnel)o).getPopName())
        && getUserState().equals(((TicTunnel)o).getUserState())
        && getAdminState().equals(((TicTunnel)o).getAdminState())
        && getPassword().equals(((TicTunnel)o).getPassword())
        && getHeartbeatInterval() == ((TicTunnel)o).getHeartbeatInterval()
        && getMtu() == ((TicTunnel)o).getMtu()
        ;
  }

  @Override
  public int hashCode() {
    return (tunnelId == null) ? 0 : tunnelId.hashCode();
  }

  @Override
  public String toString() {
    return tunnelName + " (" + tunnelId + "), " + type
        + "\n Your endpoint " + ipv6Endpoint;
  }

  public void setCreationDate(Date date) {
    creationDate = date;
  }
}
