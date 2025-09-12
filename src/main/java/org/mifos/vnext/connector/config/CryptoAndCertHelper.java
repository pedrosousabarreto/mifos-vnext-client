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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Getter
@Setter
public class CryptoAndCertHelper {
    private static final Logger logger = LoggerFactory.getLogger(CryptoAndCertHelper.class);

    private final PrivateKey privateKey;
    private final PublicKey caPublicKey;
    private final String caPublicKeyFingerprint;

    public CryptoAndCertHelper(String clientPrivateKeyFilePath, String caCertFilePath) throws Exception {
        // Load private key
        this.privateKey = loadPrivateKey(clientPrivateKeyFilePath);

        // Load CA public key and calculate fingerprint
        this.caPublicKey = loadPublicKeyFromCert(caCertFilePath);
        this.caPublicKeyFingerprint = calculateFingerprint(caPublicKey);
    }

    public String signString(String stringToSign) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("Private key not initialized");
        }

        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            signature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            byte[] digitalSignature = signature.sign();
            return Base64.getEncoder().encodeToString(digitalSignature);
        } catch (Exception e) {
            logger.error("Error signing string", e);
            throw new Exception("Error signing string: " + e.getMessage(), e);
        }
    }

    public boolean validateSignature(String originalString, String base64Signature, String pubKeyFingerprint) {
        try {
            // Verify the fingerprint matches our CA public key
            if (!this.caPublicKeyFingerprint.equals(pubKeyFingerprint)) {
                logger.warn("Public key fingerprint mismatch. Expected: {}, Received: {}",
                        this.caPublicKeyFingerprint, pubKeyFingerprint);
                return false;
            }

            // Verify the signature
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(caPublicKey);
            signature.update(originalString.getBytes(StandardCharsets.UTF_8));

            byte[] signatureBytes = Base64.getDecoder().decode(base64Signature);
            return signature.verify(signatureBytes);

        } catch (Exception e) {
            logger.error("Error validating signature", e);
            return false;
        }
    }

    // Helper methods for key loading and fingerprint calculation
    private PrivateKey loadPrivateKey(String filePath) throws Exception {
        try {
            String privateKeyPem = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
            privateKeyPem = privateKeyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (IOException e) {
            throw new Exception("Failed to read private key file: " + e.getMessage(), e);
        }
    }

    private PublicKey loadPublicKeyFromCert(String certFilePath) throws Exception {
        try {
            String certPem = new String(Files.readAllBytes(Paths.get(certFilePath)), StandardCharsets.UTF_8);
            // This is a simplified approach - in production you'd use a proper X.509 certificate parser
            // For now, we assume the file contains just the public key in PEM format
            certPem = certPem.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");

            byte[] certBytes = Base64.getDecoder().decode(certPem);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(certBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (IOException e) {
            throw new Exception("Failed to read CA certificate file: " + e.getMessage(), e);
        }
    }

    private String calculateFingerprint(PublicKey publicKey) throws Exception {
        try {
            // Get the encoded public key bytes
            byte[] publicKeyBytes = publicKey.getEncoded();

            // Simple fingerprint calculation (SHA-1 hash)
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(publicKeyBytes);

            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b));
            }

            return hexString.toString();
        } catch (Exception e) {
            throw new Exception("Failed to calculate public key fingerprint: " + e.getMessage(), e);
        }
    }
}