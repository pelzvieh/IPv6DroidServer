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

import de.flyingsnail.ipv6backwarddata.ayiya.TicTunnel;
import de.flyingsnail.ipv6backwarddata.ayiya.User;

public class UserAdd {

  public static void main(String[] args) {
    File dataFile = new File(args[0]);

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
        createEntityManagerFactory("IPv6BackwardServer").createEntityManager();
    EntityTransaction trans = em.getTransaction();
    trans.begin();
    em.persist(user);
    trans.commit();
    em.close();
    System.out.println("User created with Tunnel associated");
  }

}
