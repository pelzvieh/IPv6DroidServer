/*
 * Copyright (c) 2020 Dr. Andreas Feldner.
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License along
 *      with this program; if not, write to the Free Software Foundation, Inc.,
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *   Contact information and current version at http://www.flying-snail.de/IPv6Droid
 *
 *
 */

package de.flyingsnail.ipv6server.dtlstransporter;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsHeartbeat;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.HeartbeatMode;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsHeartbeat;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

/**
 * A TlsServer as defined by the Bouncy Castle low level TLS API, sub-class-tuned to serve
 * for the IPv6Transport DTLS implementation. The good news is that it is not strictly necessary
 * to have any contact to the subscriber database, it only needs to check for a valid certificate
 * issued by its certification authority.
 * TODO having said that, adding CRL check should be implemented some day.
 */
class IPv6DTlsServer extends DefaultTlsServer {

  private Logger logger = Logger.getLogger(IPv6DTlsServer.class.getName());
  
  private ChainChecker chainChecker;

  private Certificate serverCertChain;

  private TlsCertificate trustedCA;
  
  private AsymmetricKeyParameter privateKey;

  private int heartbeat;

  private TlsCertificate clientCert;

  private Date expiryDate;


  /**
   * @return the expiryDate
   */
  public Date getExpiryDate() {
    return expiryDate;
  }

  public IPv6DTlsServer(int heartbeat)  {
    super(new BcTlsCrypto(new SecureRandom()));
    this.heartbeat = heartbeat;
    String[] caResourceNames = new String[]{"dtlsserver.cert", "ca.cert"};
    try {
      serverCertChain = DTLSUtils.loadCertificateChain (getCrypto(), caResourceNames);
      logger.finest("Survived DTLSUtils code");
    } catch (IOException e) {
      throw new IllegalStateException("Incorrectly bundled, failure to read certificates", e);
    }
    logger.finer("Certificate chain loaded");

    trustedCA = serverCertChain.getCertificateAt(caResourceNames.length-1);

    try {
      privateKey = DTLSUtils.loadBcPrivateKeyResource("dtlsserver.key");
      logger.finest("Survived DTLSUtils code");
    } catch (IOException e) {
      throw new IllegalStateException("Incorrectly bundled, failure to read private key", e);
    }
    logger.finer("private key loaded");
    
    chainChecker = new ChainChecker(trustedCA);
    
    // self-check configuration: we would need to accept our own certificate!
    try {
      chainChecker.checkChain(serverCertChain.getCertificateList());
      logger.finer("Trust chain checked OK");
    } catch (Exception e) {
      try {
        logger.fine("Failed to verify cert chain of server itself:\n" 
            + "\nServer -------\n-----BEGIN CERTIFICATE-----\n" 
            + Base64.getEncoder().encodeToString(serverCertChain.getCertificateAt(0).getEncoded()) 
            + "\n-----END CERTIFICATE-----\n"
            + "\n\nCA -------\n-----BEGIN CERTIFICATE-----\n" 
            + Base64.getEncoder().encodeToString(trustedCA.getEncoded()) 
            + "\n-----END CERTIFICATE-----\n"
            );
      } catch (IOException e1) {
        logger.log(Level.WARNING, "Cannot generate diagnostics for mal-configuration", e1);
      }

      throw new IllegalStateException("I wouldn't even trust myself", e);
    }
    logger.info("Constructed OK");
  }

  @Override
  protected int[] getSupportedCipherSuites() {
    return super.getSupportedCipherSuites();
  }

  @Override
  public short getHeartbeatPolicy() {
    return HeartbeatMode.peer_allowed_to_send;
  }

  @Override
  public TlsHeartbeat getHeartbeat() {
    return new DefaultTlsHeartbeat(heartbeat, 1000);
  }

  @Override
  protected ProtocolVersion[] getSupportedVersions() {
    return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
  }

  @Override
  public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
    logger.log((alertLevel == AlertLevel.fatal) ? Level.WARNING : Level.INFO, "DTLS server raised alert: " + AlertLevel.getText(alertLevel)
    + ", " + AlertDescription.getText(alertDescription), cause);
  }

  @Override
  public void notifyAlertReceived(short alertLevel, short alertDescription) {
    logger.log((alertLevel == AlertLevel.fatal) ? Level.WARNING : Level.INFO, "DTLS server received alert: " + AlertLevel.getText(alertLevel)
    + ", " + AlertDescription.getText(alertDescription));
  }

  @Override
  protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
    return DTLSUtils.loadEncryptionCredentials(context,
        serverCertChain,
        privateKey);
  }

  @Override
  protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
    @SuppressWarnings("unchecked")
    Vector<SignatureAndHashAlgorithm> clientSigAlgs = (Vector<SignatureAndHashAlgorithm>)context.getSecurityParametersHandshake().getClientSigAlgs();
    try {
      return DTLSUtils.loadSignerCredentials(context,
          clientSigAlgs,
          SignatureAlgorithm.rsa,
          serverCertChain,
          privateKey);
    } catch (NoSupportedAlgorithm noSupportedAlgorithm) {
      throw new IOException(noSupportedAlgorithm);
    }
  }

  @Override
  public CertificateRequest getCertificateRequest() throws IOException {
    short[] certificateTypes = new short[] {
        ClientCertificateType.rsa_sign,
        ClientCertificateType.dss_sign,
        ClientCertificateType.ecdsa_sign
    };

    @SuppressWarnings("rawtypes")
    Vector serverSigAlgs = null;
    if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion())) {
      serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
    }

    Vector<X500Name> caNames = new Vector<X500Name>(1);
    caNames.addElement(new X500Name(DTLSListener.TRUSTED_ISSUER));

    return new CertificateRequest(
        certificateTypes,
        serverSigAlgs,
        caNames);
  }

  @Override
  public void notifyClientCertificate(Certificate clientCertificate)
      throws IOException, TlsFatalAlert {
    TlsCertificate[] chain = clientCertificate.getCertificateList();
    logger.fine("Cert chain received of "+chain.length);
    if (chain.length == 0)
      throw new TlsFatalAlert(AlertDescription.certificate_required);
    if (logger.isLoggable(Level.INFO)) {
      for (int i = 0; i < chain.length; i++) {
        org.bouncycastle.asn1.x509.Certificate entry = org.bouncycastle.asn1.x509.Certificate.getInstance(chain[i].getEncoded());
        logger.info(" Cert["+i+"] subject: " + entry.getSubject());
      }
    }

    expiryDate = chainChecker.checkChain(chain);
    clientCert = chain [0];
  }

  /**
   * @return the clientCert
   */
  public TlsCertificate getClientCert() {
    return clientCert;
  }

  /**
   * @return the caCert
   */
  public TlsCertificate getCaCert() {
    return trustedCA;
  }

}
