package de.flyingsnail.ipv6backwarddata.admin;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import javax.persistence.TypedQuery;

import de.flyingsnail.ipv6backwarddata.ayiya.TicTunnel;
import de.flyingsnail.ipv6backwarddata.ayiya.User;
import de.flyingsnail.ipv6backwarddata.ayiya.User_;


public class UserAdd {

  public static void main(String[] args) {
    if (args.length == 0) {
      System.err.println("Syntax: UserAdd [-u|-t] [new user properties file]");
      System.err.println("Modes:");
      System.err.println("-u: Updates data of existing user, tunnel-related properties are ignored");
      System.err.println("-t: adds a new tunnel to an existing user given by Username, other user properties are ignored");
      System.err.println("default: adds a new user with exactly one tunnel");
      System.exit (127);
    }
    File dataFile = new File(args[args.length-1]);
    boolean updateUser = false;
    boolean addTunnel = false;
    if (args.length > 1)
      switch (args[0]) {
      case "-u":
        updateUser = true;
        break;
      case "-t":
        addTunnel = true;
        break;
      }

    Properties data = new Properties();
    try {
      data.load(new FileInputStream(dataFile));
    } catch (FileNotFoundException e) {
      System.err.println("File not found: " + args[0]);
      System.exit(1);
    } catch (IOException e) {
      System.err.println("Cannot read file: " + args[0]);
      System.exit(2);
    }
    
    User user = new User(data.getProperty("uId"));
    user.setEmailAddress(data.getProperty("EmailAddress"));
    user.setName(data.getProperty("Name"));
    user.setPassword(data.getProperty("UserPassword"));
    user.setUsername(data.getProperty("Username"));
    
    TicTunnel tunnel = new TicTunnel(data.getProperty("tId"));
    tunnel.setTunnelId(data.getProperty("TunnelId"));
    tunnel.setType (data.getProperty("Type"));
    try {
      tunnel.setIpv6Endpoint (data.getProperty("IPv6Endpoint"));
    } catch (UnknownHostException e) {
      System.err.println("IPv6Endpoint cannot be resolved: " + data.getProperty("IPv6Endpoint"));
    }
    try {
      tunnel.setIpv6Pop (data.getProperty("IPv6PoP"));
    } catch (UnknownHostException e) {
      System.err.println("IPv6Endpoint cannot be resolved: " + data.getProperty("IPv6PoP"));
    }
    tunnel.setPrefixLength (Integer.valueOf(data.getProperty("IPv6PrefixLength")));
    tunnel.setPopName (data.getProperty("PoPName"));
    tunnel.setUserState (data.getProperty("UserState"));
    tunnel.setAdminState (data.getProperty("AdminState"));
    tunnel.setPassword (data.getProperty("Password"));
    tunnel.setHeartbeatInterval (Integer.valueOf(data.getProperty("HeartbeatInterval")));
    tunnel.setMtu (Integer.valueOf(data.getProperty("TunnelMTU")));
    tunnel.setTunnelName (data.getProperty("TunnelName"));
    tunnel.setCreationDate (new Date());
    
    List<TicTunnel> tunnels = new ArrayList<TicTunnel>(0);
    tunnels.add(tunnel);
    user.setTunnels(tunnels);
    
    EntityManager em = Persistence.
        createEntityManagerFactory("IPv6Directory").createEntityManager();
    EntityTransaction trans = em.getTransaction();
    trans.begin();
    if (updateUser) {
      //TODO: Load user from DB, update updateble fields, write back
      System.err.println("Not yet implemented");
    } else if (addTunnel) {
      CriteriaBuilder cb = em.getCriteriaBuilder();
      CriteriaQuery<User> q = cb.createQuery(User.class);
      Root<User> userRoot = q.from(User.class);
      q.where(cb.equal(userRoot.get(User_.username), user.getUsername()));
      TypedQuery<User> tq = em.createQuery(q);
      User userForUpdate = tq.getSingleResult();
      List<TicTunnel> tunnelsForUpdate = userForUpdate.getTunnels();
      tunnelsForUpdate.add(tunnel);
      userForUpdate.setTunnels(tunnelsForUpdate);
      em.persist(userForUpdate);
    } else {
      em.persist(user);
    }
    trans.commit();
    em.close();
    System.out.println("User created with Tunnel associated");
  }

}
