package de.flyingsnail.ipv6backwardserver.directory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;

import de.flyingsnail.ipv6backwarddata.ayiya.User;
import de.flyingsnail.ipv6backwarddata.ayiya.User_;
import de.flyingsnail.ipv6backwarddata.ayiya.TicTunnel;
import de.flyingsnail.ipv6backwarddata.ayiya.TicTunnel_;

public class DirectoryQueryHandler extends Thread {
  private Socket socket;
  private BufferedReader in;
  private BufferedWriter out;
  private Logger logger;
  private String userName;
  private String challenge;
  private DirectoryData directoryData;
  private String response;
  private User authenticatedUser;
  static Pattern patternClientId = Pattern.compile("client TIC/draft-00 ([.\\-,:+ \\w\\d]+)/(\\S+) (\\w+)/(\\S+)");
  static Pattern patternUsername = Pattern.compile("username ([.\\-+\\w\\d]+)");
  static Pattern patternAuth = Pattern.compile("authenticate md5 ([[a-f][0-9][A-F]]+)");

  public DirectoryQueryHandler(Socket socket, DirectoryData directoryData) throws IOException {
    logger = Logger.getLogger(getClass().getName() + "@" + toString());
    logger.info("Constructing a new query handler for reqeust from " + socket.getRemoteSocketAddress() + "/" + socket.getPort());
    this.socket = socket;
    this.directoryData = directoryData;
    this.authenticatedUser = null;
    in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
  }

  /* (non-Javadoc)
   * @see java.lang.Thread#run()
   */
  @Override
  public void run() {
    logger.fine ("Starting protocol");
    try {
      protocolStepWelcome ();
      protocolStepClientIdentification ();
      protocolStepTimeComparison ();
      protocolStepStartTLS();
      protocolStepSendUsername();
      protocolStepRequestChallenge();
      protocolStepSendAuthentication();
      logger.log(Level.INFO, "TIC protocol succeed - entering interactive phase for user " + userName);
      while (socket.isConnected()) {
        String request = readRequest();
        if (request.startsWith("QUIT")) {
          logger.info("Client sent QUIT");
          writeResponse(200, "see you later aligator");
          break;
        } else if ("tunnel list".equals(request)) {
          replyTunnelList();
        } else if (request.startsWith("tunnel show ")) {
          String id = request.substring("tunnel show ".length());
          replyTunnelShow(id);
        }
      }
      logger.info("Session successfully finished");
    } catch (IllegalRequestException ise) {
      logger.log(Level.WARNING, "TIC session did not run the hard coded way - aborting", ise);
      try {
        writeResponse(401, "illegal request flow");
        out.flush();
      } catch (IOException e) {
        // our goodbye did not arrive, not a problem
      }
    } catch (AuthenticationFailedException afe) {
      logger.log(Level.WARNING, "authentication failed", afe);
      try {
        writeResponse(301, "authentication failed, goodbye");
        out.flush();
      } catch (IOException e) {
        // our goodbye did not arrive, not a problem
      }
    } catch (Exception e) {
      logger.log(Level.WARNING, "TIC protocol did not succeed - aborting", e);
      try {
        out.write("501 internal server error");out.newLine();
        out.flush();
      } catch (IOException f) {
        // our goodbye did not arrive, not a problem
      }
    } catch (Throwable t) {
      logger.log(Level.SEVERE, "Fatal error during TIC protocol", t);
      throw t;
    } finally {
      try {
        socket.close();
      } catch (IOException e) {
        logger.severe("Failed to close communication socket");
      }
    }
  }

  /**
   * @param request
   * @throws IOException
   */
  private void replyTunnelShow(String id) throws IOException {
    logger.log(Level.INFO, "Client requested details for tunnel id {0}", id);

    TicTunnel tunnel = null;
    for (TicTunnel compare: authenticatedUser.getTunnels())
      if (compare.getTunnelId().equals(id)) {
        tunnel = compare;
        break;
      }
    if (tunnel == null) {
      logger.log(Level.WARNING, "Request was made for tunnel id {0}, which is not associated with user {1}", 
          new Object[]{id, userName});
      writeResponse(402, "No such tunnel");
      return;
    }
    
    // the requested tunnel is associated with the user, we provide its data
    writeResponse(200, "Tunnel description follows");
    out.write("TunnelId: ");out.write(id);out.newLine();
    out.write("Type: ");out.write(tunnel.getType());out.newLine();
    out.write("IPv6 Endpoint: ");out.write(tunnel.getIpv6Endpoint().getHostAddress());out.newLine();
    out.write("IPv6 PoP: ");out.write(tunnel.getIpv6Pop().getHostAddress());out.newLine();
    out.write("IPv6 PrefixLength: ");out.write(String.valueOf(tunnel.getPrefixLength()));out.newLine();
    out.write("PoP Name: ");out.write(tunnel.getPopName());out.newLine();
    out.write("IPv4 PoP: ");out.write(socket.getLocalAddress().getHostAddress());out.newLine();
    out.write("UserState: ");out.write(tunnel.getUserState());out.newLine();
    out.write("AdminState: ");out.write(tunnel.getAdminState());out.newLine();
    out.write("Password: ");out.write(tunnel.getPassword());out.newLine();
    out.write("Heartbeat_Interval: ");out.write(String.valueOf(tunnel.getHeartbeatInterval()));out.newLine();
    out.write("Tunnel MTU: ");out.write(String.valueOf(tunnel.getMtu()));out.newLine();         
    out.write("Tunnel Name: ");out.write(tunnel.getTunnelName());out.newLine();
    out.write("202\n");
    out.flush();
  }

  /**
   * @throws IOException
   */
  private void replyTunnelList() throws IOException {
    logger.info("Client requested tunnel list");
    out.write("200 tunnel list goes here\n");
    for (TicTunnel tunnel: authenticatedUser.getTunnels()) {
      out.write(MessageFormat.format("{0} {1}\n", tunnel.getTunnelId(), tunnel.getTunnelName()));
    }
    out.write("202\n");
    out.flush();
  }

  private void protocolStepWelcome() throws IOException, IllegalRequestException {
    writeResponse(200, "Welcome to the museum of historical tcp based protocols");
  }

  
  private void protocolStepClientIdentification() throws IOException, IllegalRequestException {
    String clientId = readRequest();
    Matcher matcher = patternClientId.matcher(clientId);
    if (matcher.matches()) {
      MatchResult result = matcher.toMatchResult();
      String clientName = result.group(1);
      String clientVersion = result.group(2);
      String os = result.group(3);
      String osVersion = result.group(4);
      logger.log(Level.INFO, "Client identified as " + clientName + "/" + clientVersion + " running on " + os + "/" + osVersion);
      writeResponse(200, "Welcome "+ clientName);
    } else {
      logger.log(Level.WARNING, "Client identifiation (" + clientId + ") does not match pattern");
      throw new IllegalRequestException ("Invalid client identification");
    }
  }

  private void protocolStepTimeComparison() throws IOException, IllegalRequestException {
    String request = readRequest();
    if (!request.equals("get unixtime")) {
      throw new IllegalRequestException ("client did not ask for unix time: " + request);
    }
    long timeSecs = new Date().getTime() / 1000l;
    logger.log(Level.INFO, "Client asked for unix time");
    writeResponse(200, String.valueOf(timeSecs));
  }

  private void protocolStepStartTLS() throws IOException, IllegalRequestException {
    String request = readRequest();
    if (!request.equals("STARTTLS")) {
      throw new IllegalRequestException ("client did not ask to start TLS: " + request);
    }
    // TODO implement TLS
    logger.warning("We're failing to switch to TLS");
    writeResponse(300, "STARTTLS is not yet implemented");
/*
        try {
            requestResponse("STARTTLS");
        } catch (ConnectionFailedException e) {
            // @todo is this really a good idea? Are all TIC servers around guaranteed to offer TLS?
            Log.i(TAG, "Server did not accept TLS encryption, going on with plain socket");
            return;
        }
        Log.i(TAG, "Switching to SSL encrypted connection");

        SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        socket = socketFactory.createSocket(socket,
                config.getServer(),
                TIC_PORT,
                true);
        initLineReaderAndWriter();
    
 */
  }

  private void protocolStepSendUsername() throws IOException, IllegalRequestException {
    String request = readRequest();
    Matcher matcher = patternUsername.matcher(request);
    if (matcher.matches()) {
      userName = matcher.group(1);
      logger.info("client presented as user " + userName);
      writeResponse(200, "Continue " + userName);
    } else {
      throw new IllegalRequestException("client did not send a username: " + request);
    }
  }

  private void protocolStepRequestChallenge() throws IOException, IllegalRequestException {
    String request = readRequest();
    if (!request.equals("challenge md5")) {
      throw new IllegalRequestException ("client did not ask to start TLS: " + request);
    }
    SecureRandom random = new SecureRandom();
    byte[] challengeBytes = new byte[16];
    random.nextBytes(challengeBytes);
    challenge = String.format("%032x", new BigInteger(1, challengeBytes));
    logger.info("Sent challenge to client");
    writeResponse(200, challenge);
  }

  private void protocolStepSendAuthentication() throws IOException, IllegalRequestException, AuthenticationFailedException {
    String request = readRequest();
    Matcher matcher = patternAuth.matcher(request);
    if (matcher.matches()) {
      response = matcher.group(1);
      logger.info("client presented response to md5 challenge");
      authenticatedUser = checkCredentials();
      writeResponse(200, "Welcome " + userName);
    } else {
      throw new IllegalRequestException("client did not send a response to md5 challenge: " + request);
    }
  }

  private User checkCredentials() throws AuthenticationFailedException {
    // try to read the indicated user from our database
    User u;
    String password;
    // try if the user exists
    // !! it is important that this check does not have a noticeable impact on runtime !!
    try {
      u = getUserFromDatabase(userName);
      password = u.getPassword();
    } catch (NoResultException e) {
      logger.log(Level.WARNING, "Illegal login attempt of non-existing user {0}", userName);
      u = null;
      password = "Unsinn, gegen den geprüft wird, wenn es den User nicht gibt";
    }
    // try to verify the given MD5 response
    String signature;
    try {
        // actually, the algorithm is a bit strange...
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] pwDigest = md5.digest(password.getBytes("UTF-8"));
        String pwDigestString = String.format("%032x", new BigInteger(1, pwDigest));
        // ... as we don't use this as a digest, but the bytes from its hexdump string =8-O
        pwDigest = pwDigestString.getBytes("UTF-8");

        // now let's calculate the response to the challenge
        md5.reset();
        md5.update(challenge.getBytes("UTF-8")); // probably the challenge is already hexdumped by the server
        md5.update(pwDigest);
        byte[] authDigest = md5.digest();
        // the auth response is just the hex representation of the digest
        signature = String.format("%032x", new BigInteger(1, authDigest));
    } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException("MD5 algorithm not available on this server", e);
    } catch (UnsupportedEncodingException e) {
        throw new IllegalStateException("UTF-8 encoding not available on this server", e);
    }
    
    if (u == null)
      throw new AuthenticationFailedException ("Attempt to log in with a non-existing user");
    if (!signature.equals(response))
      throw new AuthenticationFailedException ("User response to challenge does not match");
    return u;
  }

  /**
   * Reads a request from in.
   */
  private String readRequest() throws IOException {
    assert (in != null && out != null);
    String request = in.readLine();
    if (request == null)
        throw new IOException ("Unexpected end of stream at TIC protocol");
    return request;
  }
  
  /**
   * Writes a response to out.
   * @param status an int giving the 3-digit status number
   * @param response a String giving the result for the previous request
   * @throws IOException
   */
  private void writeResponse (int status, String response) throws IOException {
    assert (in != null && out != null);
    out.write(String.valueOf(status));
    out.write(' ');
    out.write(response);
    out.newLine();
    out.flush();
  }
  
  
  private User getUserFromDatabase(String userId) throws NoResultException {
    CriteriaBuilder cb = directoryData.getCriteriaBuilder();
    CriteriaQuery<User> criteriaQuery = cb.createQuery(User.class);
    Root<User> user = criteriaQuery.from(User.class);
    criteriaQuery.where(cb.equal(user.get(User_.username), userId));
    TypedQuery<User> query = directoryData.getEntityManager().createQuery(criteriaQuery);
    User result = query.getSingleResult();
    return result;
  }


}
