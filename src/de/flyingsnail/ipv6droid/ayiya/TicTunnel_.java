package de.flyingsnail.ipv6droid.ayiya;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Date;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value="Dali", date="2016-06-01T16:29:02.750+0200")
@StaticMetamodel(TicTunnel.class)
public class TicTunnel_ {
	public static volatile SingularAttribute<TicTunnel, String> id;
	public static volatile SingularAttribute<TicTunnel, String> tunnelId;
	public static volatile SingularAttribute<TicTunnel, String> type;
	public static volatile SingularAttribute<TicTunnel, Inet6Address> ipv6Endpoint;
	public static volatile SingularAttribute<TicTunnel, Inet6Address> ipv6Pop;
	public static volatile SingularAttribute<TicTunnel, Integer> prefixLength;
	public static volatile SingularAttribute<TicTunnel, String> popName;
	public static volatile SingularAttribute<TicTunnel, Inet4Address> ipv4Pop;
	public static volatile SingularAttribute<TicTunnel, String> userState;
	public static volatile SingularAttribute<TicTunnel, String> adminState;
	public static volatile SingularAttribute<TicTunnel, String> password;
	public static volatile SingularAttribute<TicTunnel, Integer> heartbeatInterval;
	public static volatile SingularAttribute<TicTunnel, String> tunnelName;
	public static volatile SingularAttribute<TicTunnel, Integer> mtu;
	public static volatile SingularAttribute<TicTunnel, Date> creationDate;
}
