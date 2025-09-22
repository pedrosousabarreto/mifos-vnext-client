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
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
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
    public boolean validateSignature(String originalString, String base64Signature, String pubKeyFingerprint) {
        try {
            PublicKey serverIntermediatePublicKey = serverIntermediateCertificate.getPublicKey();
            
            logger.info("originalString "+originalString);
            logger.info("base64Signature "+base64Signature);
            logger.info("pubKeyFingerprint "+pubKeyFingerprint);

            String calculatedFingerprint = getPublicKeyFingerprint(serverIntermediatePublicKey);
            logger.info("Server Intermediate Public Key : " + calculatedFingerprint);
            
            this.serverIntermediatePublicKeyFingerprint = calculatedFingerprint;
            logger.info("this.serverIntermediatePublicKeyFingerprint "+this.serverIntermediatePublicKeyFingerprint);
            
            if (!calculatedFingerprint.equalsIgnoreCase(pubKeyFingerprint)) {
                return false;
            }

            // Verify signature
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(serverIntermediatePublicKey);            
            signature.update(originalString.getBytes(StandardCharsets.UTF_8));

            byte[] decodedSignature = Base64.getDecoder().decode(base64Signature);
            return signature.verify(decodedSignature);

        } 
        catch (Exception e) {
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
}