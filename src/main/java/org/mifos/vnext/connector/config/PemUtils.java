
package org.mifos.vnext.connector.config;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class PemUtils {

    public static PrivateKey loadPrivateKey(String filename) throws IOException,NoSuchAlgorithmException,InvalidKeySpecException {
        try (PemReader pemReader = new PemReader(new FileReader(filename))) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(content);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        }
    }
}