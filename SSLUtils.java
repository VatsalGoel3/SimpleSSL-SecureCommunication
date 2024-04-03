import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SSLUtils {

    // Holds utilities for encryption tasks
    public static CryptoUtils.EncryptionUtil EncryptionUtil;

    // Loads an X.509 certificate from a file
    public static X509Certificate loadCertificate(String certPath) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certPath)) {
            return (X509Certificate) factory.generateCertificate(fis);
        }
    }

    // Reads a PKCS#8 formatted private key from a file
    public static RSAPrivateKey readPKCS8PrivateKey(String filePath) throws Exception {
        // Read the entire private key file
        String key = new String(Files.readAllBytes(Paths.get(filePath)));

        // Clean up the PEM formatted text
        String privateKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----", "")
                                   .replaceAll(System.lineSeparator(), "")
                                   .replace("-----END PRIVATE KEY-----", "");

        // Decode the base64 text to get binary
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        // Reconstruct the key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    // Generates a random nonce (number used once)
    public static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16]; // 128-bit nonce
        random.nextBytes(nonce);
        return nonce;
    }

    // Performs XOR operation between two byte arrays (used for master secret generation)
    public static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    // Encrypts data using a public RSA key
    public static byte[] encryptData(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Decrypts data using a private RSA key
    public static byte[] decryptData(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // Computes a keyed hash (HMAC) of the given data
    public static byte[] computeKeyedHash(byte[] data, String key) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        return sha256_HMAC.doFinal(data);
    }

    // Utility class for key generation
    public static class KeyGenerator {
        // Derives a key based on the master secret and some unique information
        public static byte[] deriveKey(byte[] masterSecret, String uniqueInfo) throws Exception {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest((uniqueInfo + Arrays.toString(masterSecret)).getBytes());
        }
    }

    // Nested class to handle cryptographic operations
    public static class CryptoUtils {

        // Utility for file encryption
        public static class EncryptionUtil {

            // Encrypts a file using AES and specified key
            public static void encryptFile(byte[] keyBytes, String inputFile, String outputFile) throws Exception {
                Key key = new SecretKeySpec(keyBytes, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

                cipher.init(Cipher.ENCRYPT_MODE, key);

                try (FileInputStream inputStream = new FileInputStream(inputFile);
                     FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;

                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        byte[] output = cipher.update(buffer, 0, bytesRead);
                        if (output != null) {
                            outputStream.write(output);
                        }
                    }

                    byte[] outputBytes = cipher.doFinal();
                    if (outputBytes != null) {
                        outputStream.write(outputBytes);
                    }
                }
            }
        }

        // Utility for file decryption
        public static class DecryptionUtil {

            // Decrypts a file using AES and specified key
            public static void decryptFile(byte[] keyBytes, String inputFile, String outputFile) throws Exception {
                Key key = new SecretKeySpec(keyBytes, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

                cipher.init(Cipher.DECRYPT_MODE, key);

                try (FileInputStream inputStream = new FileInputStream(inputFile);
                     FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;

                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        byte[] output = cipher.update(buffer, 0, bytesRead);
                        if (output != null) {
                            outputStream.write(output);
                        }
                    }

                    byte[] outputBytes = cipher.doFinal();
                    if (outputBytes != null) {
                        outputStream.write(outputBytes);
                    }
                }
            }
        }
    }
}
