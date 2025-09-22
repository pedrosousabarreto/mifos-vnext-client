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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import lombok.Getter;
import lombok.Setter;


import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
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
            logger.info("Server Intermediate Public Key : " + calculatedFingerprint);
            
            this.serverIntermediatePublicKeyFingerprint = calculatedFingerprint;
            logger.debug("this.serverIntermediatePublicKeyFingerprint "+this.serverIntermediatePublicKeyFingerprint);
            
            if (!calculatedFingerprint.equalsIgnoreCase(response.getPubKeyFingerprint())) {
                return false;
            }
            
            return verifySignatureNative(response.getPubKeyFingerprint().getBytes(StandardCharsets.UTF_8),response.getPubKeyFingerprintBytes().toByteArray(),serverIntermediatePublicKey);
                        
            /*
            Security.addProvider(new BouncyCastleProvider());
            return verifySignature(
                    originalString.getBytes(StandardCharsets.UTF_8), 
                    Base64.getDecoder().decode(base64Signature.getBytes(StandardCharsets.UTF_8)), 
                    serverIntermediatePublicKey, 
                    "SHA-256WITHRSA");
            */
            /*
            for (Provider provider : Security.getProviders()) {
                Set<Provider.Service> services = provider.getServices();
                for (Provider.Service service : services) {
                    if ("Signature".equals(service.getType())) {
                        logger.info("  " + service.getAlgorithm() + " (from " + provider.getName() + ")");
                    }
                }
            }
            */
            /*
            // Verify signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(serverIntermediatePublicKey);            
            signature.update(originalString.getBytes(StandardCharsets.UTF_8));
            
            byte[] decodedSignature = Base64.getDecoder().decode(base64Signature.getBytes(StandardCharsets.UTF_8));
            
            return signature.verify(decodedSignature);*/
            

        } 
        catch (Exception e) {
            e.printStackTrace();
            logger.error("Exception "+e.getMessage());
            return false;
        }
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
    
    public static boolean verifySignatureNative(byte[] signedData, byte[] signatureBytes, PublicKey publicKey1) throws Exception {
        // 1. Obtain the Public Key from the CA Certificate
        PublicKey publicKey = publicKey1;

        // 2. Initialize the Signature Object
        Signature signature = Signature.getInstance("SHA256withRSA"); // Use the correct algorithm
        signature.initVerify(publicKey);

        // 3. Provide the Signed Data
        signature.update(signedData);

        // 4. Verify the Signature
        logger.info("signature.verify(signatureBytes) "+signature.verify(signatureBytes));
        
        return signature.verify(signatureBytes);
    }
    
    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey, String algorithm) {
        try {
            // Convert Java's PublicKey to Bouncy Castle's AsymmetricKeyParameter
            AsymmetricKeyParameter publicKeyParam = PublicKeyFactory.createKey(publicKey.getEncoded());

            // Get the appropriate Bouncy Castle signer
            Signer signer = SignerUtilities.getSigner(algorithm);

            // Initialize for verification
            signer.init(false, publicKeyParam);

            // Update with the original data
            signer.update(data, 0, data.length);

            // Verify the signature
            return signer.verifySignature(signature);
        }
            catch (Exception e){
                e.printStackTrace();
                return false;
        }
    }
    
}