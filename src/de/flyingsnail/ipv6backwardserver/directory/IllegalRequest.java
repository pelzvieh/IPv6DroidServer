package de.flyingsnail.ipv6backwardserver.directory;

public class IllegalRequest extends Exception {

  public IllegalRequest() {
  }

  public IllegalRequest(String message) {
    super(message);
  }

  public IllegalRequest(Throwable cause) {
    super(cause);
  }

  public IllegalRequest(String message, Throwable cause) {
    super(message, cause);
  }

  public IllegalRequest(String message, Throwable cause,
      boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

}
