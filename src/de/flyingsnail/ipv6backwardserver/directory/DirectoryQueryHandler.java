package de.flyingsnail.ipv6backwardserver.directory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DirectoryQueryHandler extends Thread {
  Socket socket;
  private BufferedReader in;
  private BufferedWriter out;
  private Logger logger;
  private String userName;
  private String challenge;
  static Pattern patternClientId = Pattern.compile("client TIC/draft-00 ([.\\-,:+ \\w\\d]+)/(\\S+) (\\w+)/(\\S+)");
  static Pattern patternUsername = Pattern.compile("username ([.\\-+\\w\\d]+)");
  static Pattern patternAuth = Pattern.compile("authenticate md5 ([[a-f][0-9][A-F]]+)");

  public DirectoryQueryHandler(Socket socket) throws IOException {
    logger = Logger.getLogger(getClass().getName() + "@" + toString());
    logger.info("Constructing a new query handler for reqeust from " + socket.getRemoteSocketAddress() + "/" + socket.getPort());
    this.socket = socket;
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
      // TODO read tunnel list belonging to the authenticated user
      while (socket.isConnected()) {
        String request = readRequest();
        if (request.startsWith("QUIT")) {
          logger.info("Client sent QUIT");
          writeResponse(200, "see you later aligator");
          break;
        } else if ("tunnel list".equals(request)) {
          logger.info("Client requested tunnel list");
          // TODO iterate over actual tunnel list
          out.write("200 tunnel list goes here\n");
          out.write("007 ein Tunnel\n");
          out.write("202\n");
          out.flush();
        } else if (request.startsWith("tunnel show ")) {
          writeResponse(200, "Tunnel description follows");
          // TODO  write actual tunnel data
          String id = request.substring("tunnel show ".length());
          logger.info("Client requested details for tunnel id " + id);
          out.write("TunnelId: ");out.write(id);out.newLine();
          out.write("Type: ");out.write("ayiya");out.newLine();
          out.write("IPv6 Endpoint: ");out.write("2a06:1c40:c1::2");out.newLine();
          out.write("IPv6 PoP: ");out.write("2a06:1c40:c1::1");out.newLine();
          out.write("IPv6 PrefixLength: ");out.write("64");out.newLine();
          out.write("PoP Name: ");out.write("Flying Snail");out.newLine();
          //out.write("IPv4 Endpoint: ");out.write("192.168.1.4");out.newLine();
          out.write("IPv4 PoP: ");out.write("192.168.1.135");out.newLine();
          out.write("UserState: ");out.write("enabled");out.newLine();
          out.write("AdminState: ");out.write("enabled");out.newLine();
          out.write("Password: ");out.write("geheim");out.newLine();
          out.write("Heartbeat_Interval: ");out.write("300");out.newLine();
          out.write("Tunnel MTU: ");out.write("1300");out.newLine();         
          out.write("Tunnel Name: ");out.write("Herbert");out.newLine();
          out.write("202\n");
          out.flush();
        }
      }
      logger.info("Session successfully finished");
    } catch (IllegalRequest ise) {
      logger.log(Level.WARNING, "TIC session did not run the hard coded way - aborting", ise);
      try {
        writeResponse(401, "illegal request flow");
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

  private void protocolStepWelcome() throws IOException, IllegalRequest {
    if (socket.getLocalAddress() instanceof Inet4Address) {
      writeResponse(200, "Welcome to the museum of historical tcp based protocols");
    } else {
      writeResponse(400, "You don't need to access the directory service if you have a working IPv6 connection");
      throw new IllegalRequest("we're accessed by IPv6");
    }
  }

  
  private void protocolStepClientIdentification() throws IOException, IllegalRequest {
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
      throw new IllegalRequest ("Invalid client identification");
    }
  }

  private void protocolStepTimeComparison() throws IOException, IllegalRequest {
    String request = readRequest();
    if (!request.equals("get unixtime")) {
      throw new IllegalRequest ("client did not ask for unix time: " + request);
    }
    long timeSecs = new Date().getTime() / 1000l;
    logger.log(Level.INFO, "Client asked for unix time");
    writeResponse(200, String.valueOf(timeSecs));
  }

  private void protocolStepStartTLS() throws IOException, IllegalRequest {
    String request = readRequest();
    if (!request.equals("STARTTLS")) {
      throw new IllegalRequest ("client did not ask to start TLS: " + request);
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

  private void protocolStepSendUsername() throws IOException, IllegalRequest {
    String request = readRequest();
    Matcher matcher = patternUsername.matcher(request);
    if (matcher.matches()) {
      userName = matcher.group(1);
      logger.info("client presented as user " + userName);
      writeResponse(200, "Continue " + userName);
    } else {
      throw new IllegalRequest("client did not send a username: " + request);
    }
  }

  private void protocolStepRequestChallenge() throws IOException, IllegalRequest {
    String request = readRequest();
    if (!request.equals("challenge md5")) {
      throw new IllegalRequest ("client did not ask to start TLS: " + request);
    }
    SecureRandom random = new SecureRandom();
    byte[] challengeBytes = new byte[16];
    random.nextBytes(challengeBytes);
    challenge = String.format("%032x", new BigInteger(1, challengeBytes));
    logger.info("Sent challenge to client");
    writeResponse(200, challenge);
  }

  private void protocolStepSendAuthentication() throws IOException, IllegalRequest {
    String request = readRequest();
    Matcher matcher = patternAuth.matcher(request);
    if (matcher.matches()) {
      challenge = matcher.group(1);
      logger.info("client presented response to md5 challenge");
      // @todo implement check of md5 challenge
      logger.warning("Required to implement actual check of response!!");
      writeResponse(200, "Welcome " + userName);
    } else {
      throw new IllegalRequest("client did not send a response to md5 challenge: " + request);
    }
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
}
