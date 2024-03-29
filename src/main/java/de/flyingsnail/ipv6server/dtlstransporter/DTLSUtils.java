/*
 * This class is based on test classes published by the legions of the bouncy castle.
 *
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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * This is a collection of static methods to help loading standard PEM resources into the somewhat
 * enigmatic low-level objects of Bouncy Castle DTLS implementation. Because DTLS is only available
 * from the low-level, not the JCA standard, familiar resources like java keystores cannot be easily
 * used.
 *
 * Refer to the @link{https://github.com/bcgit/bc-java/blob/master/tls/src/test/java/org/bouncycastle/tls/test/TlsTestUtils.java} BC implementation.
 */
class DTLSUtils {
  private static Logger logger = Logger.getLogger(DTLSUtils.class.getName());

  private DTLSUtils() {}
  
  public static TlsCredentialedDecryptor loadEncryptionCredentials(TlsContext context, Certificate certificate, AsymmetricKeyParameter privateKey) {
    TlsCrypto crypto = context.getCrypto();

    return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)crypto, certificate, privateKey);
  }

  public static AsymmetricKeyParameter loadBcPrivateKeyResource(String keyResource) throws IOException {
    PemObject pem = loadPemResource(keyResource);
    logger.finer(()->"Loaded PEM resource " + keyResource + ", type: " + pem.getType());
    switch (pem.getType()) {
    case "PRIVATE KEY":
      return PrivateKeyFactory.createKey(pem.getContent());
    case "RSA PRIVATE KEY":
      // this is the relevant case with the bundled resources
      RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
      logger.finest("Created RSAPrivateKey instance from PEM");
      return new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(),
          rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(),
          rsa.getExponent2(), rsa.getCoefficient());
    case "EC PRIVATE KEY":
      ECPrivateKey pKey = ECPrivateKey.getInstance(pem.getContent());
      AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, 
          pKey.getParametersObject());
      PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
      return PrivateKeyFactory.createKey(privInfo);
    case "ENCRYPTED PRIVATE KEY":
      throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
      
    default: 
      throw new IllegalArgumentException("No supported private key in resource " + keyResource);
    }
  }

  public static AsymmetricKeyParameter parseBcPrivateKeyString(String keyString) throws IOException {
    PemObject pem = parsePemString(keyString);
    switch (pem.getType()) {
    case "PRIVATE KEY":
      return PrivateKeyFactory.createKey(pem.getContent());
    case "RSA PRIVATE KEY":
      // this is the relevant case with the bundled resources
      RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
      return new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(),
          rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(),
          rsa.getExponent2(), rsa.getCoefficient());
    case "EC PRIVATE KEY":
      ECPrivateKey pKey = ECPrivateKey.getInstance(pem.getContent());
      AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, 
          pKey.getParametersObject());
      PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
      return PrivateKeyFactory.createKey(privInfo);
    case "ENCRYPTED PRIVATE KEY":
      throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
    default:
      throw new IllegalArgumentException("No supported private key encoded in supplied string");
    }
  }

  public static Certificate loadCertificateChain (TlsContext context, String[] certResources) throws IOException {
    return loadCertificateChain(context.getCrypto(), certResources);
  }

  public static Certificate loadCertificateChain(TlsCrypto crypto, String[] certResources) throws IOException {
    TlsCertificate[] chain = new TlsCertificate[certResources.length];
    for (int i = 0; i < certResources.length; ++i)
    {
      chain[i] = loadCertificateResource(crypto, certResources[i]);
    }
    return new Certificate(chain);
  }

  /**
   * Parse the supplied List of PEM encoded strings into a Certificate object representing
   * the whole chain.
   * @param crypto the TlsCrypto object to use.
   * @param certStrings a List&lt;String&gt; giving this instance's certificate at position 0
   *                    and the trusted CA's certificate as the last element. All strings are
   *                    expected to be PEM encoded X509 certificates.
   * @return a Certificate representing the certificate chain.
   * @throws IOException in case of parsing errors
   */
  public static Certificate parseCertificateChain(TlsCrypto crypto, List<String> certStrings) throws IOException {
    ArrayList<TlsCertificate> chain = new ArrayList<>(certStrings.size());
    for (String certString: certStrings) {
      chain.add(parseCertificateString(crypto, certString));
    }
    return new Certificate(chain.toArray(new TlsCertificate[0]));
  }

  private static TlsCertificate loadCertificateResource(TlsCrypto crypto, String certResource) throws IOException {
    PemObject pem = loadPemResource(certResource);
    if (pem.getType().endsWith("CERTIFICATE")) {
      return crypto.createCertificate(pem.getContent());
    }
    throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
  }

  private static TlsCertificate parseCertificateString(TlsCrypto crypto, String certString) throws IOException {
    PemObject pem = parsePemString(certString);
    if (pem.getType().endsWith("CERTIFICATE")) {
      return crypto.createCertificate(pem.getContent());
    }
    throw new IllegalArgumentException("Supplied PEM string doesn't specify a valid certificate");
  }

  private static PemObject loadPemResource(String pemResource) throws IOException {
    InputStream s = DTLSUtils.class.getResourceAsStream(pemResource);
    if (s == null) {
      throw new IOException("Resource "+ pemResource + " not found in classpath");
    }
    PemReader p = new PemReader(new InputStreamReader(s));
    PemObject o = p.readPemObject();
    p.close();
    return o;
  }

  private static PemObject parsePemString(String pemString) throws IOException {
    PemReader p = new PemReader(new StringReader(pemString));
    PemObject o = p.readPemObject();
    p.close();
    return o;
  }

  @SuppressWarnings("unchecked")
  private static SignatureAndHashAlgorithm algorithmForCode (List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, short signatureAlgorithm)  throws NoSupportedAlgorithm {
    if (supportedSignatureAlgorithms == null) {
      supportedSignatureAlgorithms = ((Vector<SignatureAndHashAlgorithm>)TlsUtils.getDefaultSignatureAlgorithms(signatureAlgorithm));
    }

    SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
    for (SignatureAndHashAlgorithm alg: supportedSignatureAlgorithms) {
      if (alg.getSignature() == signatureAlgorithm) {
        // Just grab the first one we find
        signatureAndHashAlgorithm = alg;
        break;
      }
    }

    if (signatureAndHashAlgorithm == null) {
      throw new NoSupportedAlgorithm("None of the supported signature algorithms generates the required signature type");
    }
    return signatureAndHashAlgorithm;
  }

  public static TlsCredentialedSigner loadSignerCredentials(TlsContext context,
      List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms,
      short signatureAlgorithm,
      String[] certResources,
      String keyResource) throws IOException, NoSupportedAlgorithm {

    Certificate certificate = loadCertificateChain(context, certResources);
    AsymmetricKeyParameter privateKey = loadBcPrivateKeyResource(keyResource);

    return loadSignerCredentials(context, supportedSignatureAlgorithms, signatureAlgorithm,
        certificate, privateKey);
  }



  public static TlsCredentialedSigner loadSignerCredentials(TlsContext context,
      List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms,
      short signatureAlgorithm,
      Certificate certificate,
      AsymmetricKeyParameter privateKey) throws NoSupportedAlgorithm {
    TlsCrypto crypto = context.getCrypto();
    TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
    SignatureAndHashAlgorithm signatureAndHashAlgorithm = algorithmForCode(supportedSignatureAlgorithms, signatureAlgorithm);

    return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto)crypto, privateKey, certificate, signatureAndHashAlgorithm);
  }

  public static boolean areSameCertificate(TlsCertificate a, TlsCertificate b) throws IOException {
    return Arrays.areEqual(a.getEncoded(), b.getEncoded());
  }

  /**
   * Examines the SubjectAlternateNames extensions of the supplied certificate and probes for one
   * of type IPAdress. Reconstructs the IP address from the hexdump representation and returns
   * the first name found to be an IPv6Adress.
   * @param cert the TlsCertificate to read a subjectAlternativeName IPv6 address from
   * @return null if no matching extension was found or the Inet6Adress reconstructed from cert
   * @throws IOException on encoding errors on the ASN 1 level
   */
  public static Inet6Address getIpv6AlternativeName(TlsCertificate cert) throws IOException {
    try {
      Extensions extensions = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded()).getTBSCertificate().getExtensions();
      if (extensions == null) {
          logger.info("No certificate extensions presented");
          return null;
      }
      GeneralNames generalNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
      for (GeneralName generalName : generalNames.getNames()) {
          if (generalName.getTagNo() == GeneralName.iPAddress) {
              InetAddress inetAddress = InetAddress.getByAddress(
                      new BigInteger(generalName.getName().toString().substring(1), 16).toByteArray());
              if (inetAddress instanceof Inet6Address) {
                  logger.fine(()->"Supplied cert contains IPv6 subject alternative name: " + inetAddress);
                  return (Inet6Address)inetAddress;
              } else {
                  logger.finer(()->"Found subject alternative name IP address, but not IPv6: " + inetAddress);
              }
          } else {
              logger.finest(()-> "Found subject alternative name which is not IP: " + generalName.getName());
          }
      }
      logger.fine("Supplied cert did not contain an IPv6 subject alternative name");
  } catch (Exception e) {
      logger.log(Level.WARNING, "severe problem occurred while extracting information from certificate", e);
  }
  return null;
  }
}
