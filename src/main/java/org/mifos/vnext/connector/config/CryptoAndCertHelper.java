/**
 * Licensed to the Mifos Initiative under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.mifos.vnext.connector.config;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import lombok.Getter;
import lombok.Setter;


import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Security;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mifos.grpc.proto.vnext.StreamServerInitialResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Getter
@Setter
public class CryptoAndCertHelper {
    
    private static final Logger logger = LoggerFactory.getLogger(CryptoAndCertHelper.class);
    
    private final PrivateKey clientPrivateKey;    
    private final X509Certificate serverIntermediateCertificate;
    private String serverIntermediatePublicKeyFingerprint;

    public CryptoAndCertHelper(String clientPrivateKeyFilePath, String serverIntermediateCertificatePath) 
            throws Exception {
        logger.info("clientPrivateKeyFilePath "+clientPrivateKeyFilePath);
        logger.info("serverIntermediateCertificatePath "+serverIntermediateCertificatePath);
        // Load private key (PEM -> PrivateKey)
        this.clientPrivateKey = PemUtils.loadPrivateKey(clientPrivateKeyFilePath);
        
        // Load CA intermediate certificate
        try (FileInputStream fis = new FileInputStream(serverIntermediateCertificatePath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            this.serverIntermediateCertificate = (X509Certificate) factory.generateCertificate(fis);
        }
        
        Security.addProvider(new BouncyCastleProvider());
        
    }

    /**
     * Signs a string using the loaded private key (SHA1withRSA).
     */
    public String signString(String stringToSign) throws Exception {
        if (clientPrivateKey == null) {
            throw new IllegalStateException("Could not find private key");
        }

        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(clientPrivateKey);
            signature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signedBytes = signature.sign();

            return Base64.getEncoder().encodeToString(signedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error signing string", e);
        }
    }
    

    /**
     * Validates a signature with Server Intermediate CA public key + fingerprint.
     */
    public boolean validateSignature(String originalString, StreamServerInitialResponse response) {
        try {
            PublicKey serverIntermediatePublicKey = serverIntermediateCertificate.getPublicKey();
            
            logger.info("originalString "+originalString);
            logger.info("base64Signature "+response.getSignedClientId());
            logger.info("pubKeyFingerprint "+response.getPubKeyFingerprint());

            String calculatedFingerprint = getPublicKeyFingerprint(serverIntermediatePublicKey);
            logger.info("Calculated Fingerprint Server Intermediate Public Key : " + calculatedFingerprint);
            
            this.serverIntermediatePublicKeyFingerprint = calculatedFingerprint;
                    
            if (!calculatedFingerprint.equalsIgnoreCase(response.getPubKeyFingerprint())) {
                return false;
            }
                     
            byte[] signatureBytes = Base64.getDecoder().decode(response.getSignedClientId());
             
            // Create SHA-1 digest instance
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            // Update digest with the input string (UTF-8 encoded)
            byte[] digest = md.digest(originalString.getBytes(StandardCharsets.UTF_8));
            
            Signature sig = Signature.getInstance("SHA1withRSA");            
            sig.initVerify(serverIntermediatePublicKey);
            sig.update(digest);
            sig.verify(signatureBytes);
            
            logger.info("Signature verified "+sig.verify(signatureBytes));
                         
            return false;
        } 
        catch (Exception e) {
            e.printStackTrace();
            logger.error("Exception "+e.getMessage());
            return false;
        }
    }
    
    private static final char[] hex = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static String byteArray2Hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (final byte b : bytes) {
            sb.append(hex[(b & 0xF0) >> 4]);
            sb.append(hex[b & 0x0F]);
        }
        logger.info("byteArray2Hex "+sb.toString());
        return sb.toString();
    }
           
    public String getPublicKeyFingerprint(PublicKey publicKey) throws Exception {
        
        byte[] skiExtension = serverIntermediateCertificate.getExtensionValue("2.5.29.14");
        byte[] skiBytes = null;
        
        if (skiExtension != null) {
            try (ASN1InputStream ais = new ASN1InputStream(skiExtension)) {
                DEROctetString oct = (DEROctetString) ais.readObject();
                try (ASN1InputStream ais2 = new ASN1InputStream(oct.getOctets())) {
                    DEROctetString skiOctet = (DEROctetString) ais2.readObject();
                    skiBytes = skiOctet.getOctets();
                }
            }
        }
        
        StringBuilder hexSki = new StringBuilder();
        
        if (skiBytes != null) {
            for (byte b : skiBytes) {
                hexSki.append(String.format("%02x", b));
            }
        }
        
        String subjectKeyIdentifier = hexSki.toString();
        logger.debug("Subject Key Identifier: " + subjectKeyIdentifier);        
        return subjectKeyIdentifier;
    }
    
    // String compatible with node.js crypto module!
    static String node_rsa_init = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static String encryptStringWithPublicKey(String s, String keyFilename) throws Exception {
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PublicKey pubkey = readPublicKeyFromPem(keyFilename);
        // encrypt
        // cipher init compatible with node.js crypto module!
        cipher.init(Cipher.ENCRYPT_MODE, pubkey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        String enc = Base64.getEncoder().encodeToString(cipher.doFinal(s.getBytes("UTF-8")));
        return enc;
    }

    public static String decryptStringWithPrivateKey(String s, String keyFilename)  throws Exception {
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PrivateKey pkey = readPrivateKeyFromPem(keyFilename);
        // cipher init compatible with node.js crypto module!
        cipher.init(Cipher.DECRYPT_MODE, pkey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        String dec = new String(cipher.doFinal(Base64.getDecoder().decode(s)), "UTF-8");
        return dec;
    }
    /*
    public static String encryptStringWithPublicKey(String s, String keyFilename) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        PublicKey pubkey = readPublicKeyFromPem(keyFilename);
        cipher.init(Cipher.ENCRYPT_MODE, pubkey);
        String enc = Base64.getEncoder().encodeToString(cipher.doFinal(s.getBytes("UTF-8")));
        return enc;
    }
  
    public static String decryptStringWithPrivateKey(String s, String keyFilename)  throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        PrivateKey pkey = readPrivateKeyFromPem(keyFilename);
        cipher.init(Cipher.DECRYPT_MODE, pkey);
        String dec = new String(cipher.doFinal(Base64.getDecoder().decode(s)), "UTF-8");
 
        return dec;
    }*/
  
    public static PrivateKey readPrivateKeyFromPem(String keyFilename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(keyFilename).toPath());
        String keyString = new String(keyBytes);
  
        if (keyString.contains("BEGIN PRIVATE KEY")) {
            // PCKS8 format key
            return readPrivateKeyFromPem_PKCS8(keyFilename);
        }
        else if(keyString.contains("BEGIN RSA PRIVATE KEY")){
            // PCKS1 format key
            return readPrivateKeyFromPem_PKCS1(keyFilename);
        }
        // unknown format
        throw new Exception("Unknown private key format in "+keyFilename);
    }
    
    
    
    
    public static void encryptDecrypt(){
        try {
            // Key file names
            String pubkeyfile = "/home/fintecheando/dev/fintecheando/vnext/llaves/mifos-bank-1_public.pem";
            String privateKeyfile = "/home/fintecheando/dev/fintecheando/vnext/llaves/mifos-bank-1_private.pem";
  
            // encrypt
            String s = "73da6a2d-67b2-4d13-8877-b4916e63c6b4"; 
            // Get the Base64 encoder
            Base64.Encoder encoder = Base64.getEncoder();

            // Convert the string to bytes using a specific charset (e.g., UTF-8)
            byte[] stringBytes = s.getBytes(StandardCharsets.UTF_8);

            // Encode the byte array to a Base64 string
            String encodedString = encoder.encodeToString(stringBytes);
            logger.info("encodedString "+encodedString);
            
            
            String enc = encryptStringWithPublicKey(s, pubkeyfile);
            logger.info( "ENCRIPTADO "+ String.format("%s -> %s", s, enc));
  
            // decrypt
            String dec = decryptStringWithPrivateKey(enc, privateKeyfile);
            logger.info( "DESENCRIPTADO "+String.format("%s -> %s", enc, dec));
        }
        catch(Exception ex){
            logger.error(ex.getMessage());
        }
    }
  
    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public static PrivateKey readPrivateKeyFromPem_PKCS8(String keyFilename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(keyFilename).toPath());
        String keyString = new String(keyBytes);
        String privKeyPEM = keyString.replace("-----BEGIN PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("\r", "");
        privKeyPEM = privKeyPEM.replace("\n", "");
        keyBytes = Base64.getDecoder().decode(privKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
  
    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    public static PublicKey readPublicKeyFromPem(String keyFilename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(keyFilename).toPath());
        String keyString = new String(keyBytes);
        String privKeyPEM = keyString.replace("-----BEGIN PUBLIC KEY-----", "");
        privKeyPEM = privKeyPEM.replace("-----END PUBLIC KEY-----", "");
        privKeyPEM = privKeyPEM.replace("\r", "");
        privKeyPEM = privKeyPEM.replace("\n", "");
        keyBytes = Base64.getDecoder().decode(privKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
  
    // https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/55339208#55339208
    // https://github.com/Mastercard/client-encryption-java/blob/master/src/main/java/com/mastercard/developer/utils/EncryptionUtils.java
    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public static PrivateKey readPrivateKeyFromPem_PKCS1(String keyFilename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(keyFilename).toPath());
        String keyString = new String(keyBytes);
        String privKeyPEM = keyString.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("\r", "");
        privKeyPEM = privKeyPEM.replace("\n", "");
  
        keyBytes = Base64.getDecoder().decode(privKeyPEM);
  
        // We can't use Java internal APIs to parse ASN.1 structures, so we build a PKCS#8 key Java can understand
        int pkcs1Length = keyBytes.length;
        int totalLength = pkcs1Length + 22;
        byte[] pkcs8Header = new byte[] {
                0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff), // Sequence + total length
                0x2, 0x1, 0x0, // Integer (0)
                0x30, 0xD, 0x6, 0x9, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0, // Sequence: 1.2.840.113549.1.1.1, NULL
                0x4, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) // Octet string + length
        };
        keyBytes = join(pkcs8Header, keyBytes);
  
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
  
    private static byte[] join(byte[] byteArray1, byte[] byteArray2){
        byte[] bytes = new byte[byteArray1.length + byteArray2.length];
        System.arraycopy(byteArray1, 0, bytes, 0, byteArray1.length);
        System.arraycopy(byteArray2, 0, bytes, byteArray1.length, byteArray2.length);
        return bytes;
    }
    
    
    
}