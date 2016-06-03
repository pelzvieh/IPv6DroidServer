package de.flyingsnail.ipv6backwardserver.directory;

/**
 * An exception indicating a protocol violation.
 * @author pelzi
 *
 */
public class IllegalRequestException extends Exception {

  private static final long serialVersionUID = -7691992784785287352L;

  public IllegalRequestException() {
  }

  public IllegalRequestException(String message) {
    super(message);
  }

  public IllegalRequestException(Throwable cause) {
    super(cause);
  }

  public IllegalRequestException(String message, Throwable cause) {
    super(message, cause);
  }

  public IllegalRequestException(String message, Throwable cause,
      boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

}
