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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PKIXRevocationChecker.Option;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
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

  private Certificate certChain;

  private TlsCertificate trustedCA;
  
  private Set<TrustAnchor> trustAnchors;

  private AsymmetricKeyParameter privateKey;

  private int heartbeat;

  private TlsCertificate clientCert;

  private final CertificateFactory certificateFactory;

  private PKIXRevocationChecker revocationChecker;

  private CertPathBuilder certPathBuilder;


  public IPv6DTlsServer(int heartbeat)  {
    super(new BcTlsCrypto(new SecureRandom()));
    this.heartbeat = heartbeat;
    String[] caResourceNames = new String[]{"dtlsserver.cert", "ca.cert"};
    try {
      certChain = DTLSUtils.loadCertificateChain (getCrypto(), caResourceNames);
    } catch (IOException e) {
      throw new IllegalStateException("Incorrectly bundled, failure to read certificates", e);
    }

    trustedCA = certChain.getCertificateAt(caResourceNames.length-1);

    try {
      privateKey = DTLSUtils.loadBcPrivateKeyResource("dtlsserver.key");
    } catch (IOException e) {
      throw new IllegalStateException("Incorrectly bundled, failure to read private key", e);
    }
    try {
      certificateFactory = CertificateFactory.getInstance("x.509");
    } catch (CertificateException e) {
      throw new IllegalStateException("No x.509 certificate factory available");
    }
    
    trustAnchors = new HashSet<>();
    try {
      trustAnchors.add(
          new TrustAnchor ((X509Certificate) certificateFactory.generateCertificate(
              new ByteArrayInputStream(trustedCA.getEncoded())),
              null
          )
      );
    } catch (CertificateException | IOException e) {
      throw new IllegalStateException("Cannot create trust anchors", e);
    }
    
    try {
      certPathBuilder = CertPathBuilder.getInstance("PKIX");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("No PKIX cert path builder available", e);
    }
    
    revocationChecker = (PKIXRevocationChecker)certPathBuilder.getRevocationChecker();
    revocationChecker.setOptions(EnumSet.of(Option.PREFER_CRLS));
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
        certChain,
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
          certChain,
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
      throws IOException {
    TlsCertificate[] chain = clientCertificate.getCertificateList();
    logger.fine("Cert chain received of "+chain.length);
    if (chain.length == 0)
      throw new TlsFatalAlert(AlertDescription.certificate_required);
    for (int i = 0; i < chain.length; i++) {
      org.bouncycastle.asn1.x509.Certificate entry = org.bouncycastle.asn1.x509.Certificate.getInstance(chain[i].getEncoded());
      logger.info(" Cert["+i+"] subject: " + entry.getSubject());
    }

    clientCert = chain [0];
    X509CertSelector target = new X509CertSelector();
    try {
      java.security.cert.X509Certificate myStdCert = (X509Certificate)certificateFactory.generateCertificate(
          new ByteArrayInputStream(clientCert.getEncoded())
      );
      target.setCertificate(myStdCert);
    } catch (CertificateException e) {
      throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
    }
    
    PKIXBuilderParameters params;
    try {
      params = new PKIXBuilderParameters(trustAnchors, target);
      CertStoreParameters intermediates = new CollectionCertStoreParameters(Arrays.asList(chain));
      params.addCertStore(CertStore.getInstance("Collection", intermediates));
      params.addCertPathChecker(revocationChecker);
      certPathBuilder.build(params);
      logger.info("Client authenticated by valid certificate chain");
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new TlsFatalAlert(AlertDescription.internal_error, e);
    } catch (CertPathBuilderException e) {
      throw new TlsFatalAlert (AlertDescription.unknown_ca);
    }
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
