package de.flyingsnail.ipv6backwardserver.directory;

import de.flyingsnail.ipv6droid.ayiya.TicTunnel;
import javax.annotation.Generated;
import javax.persistence.metamodel.ListAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value="Dali", date="2016-06-01T13:39:02.716+0200")
@StaticMetamodel(User.class)
public class User_ {
	public static volatile SingularAttribute<User, String> id;
	public static volatile SingularAttribute<User, String> username;
	public static volatile SingularAttribute<User, String> password;
	public static volatile ListAttribute<User, TicTunnel> tunnels;
	public static volatile SingularAttribute<User, String> name;
	public static volatile SingularAttribute<User, String> emailAddress;
}
