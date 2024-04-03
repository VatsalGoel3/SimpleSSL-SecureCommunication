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
    public static CryptoUtils.EncryptionUtil EncryptionUtil;

    public static X509Certificate loadCertificate(String certPath) throws Exception { // Certificate Input
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(certPath);
        return (X509Certificate) factory.generateCertificate(fis);
    }

    public static RSAPrivateKey readPKCS8PrivateKey(String filePath) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filePath)));

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    // Simplified method to generate a random nonce
    public static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16]; // 128-bit nonce
        random.nextBytes(nonce);
        return nonce;
    }

    // Simplified method to XOR two byte arrays (for master secret generation)
    public static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static byte[] encryptData(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Method to decrypt data using a private key
    public static byte[] decryptData(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static byte[] computeKeyedHash(byte[] data, String key) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        return sha256_HMAC.doFinal(data);
    }

    public static class KeyGenerator {
        public static byte[] deriveKey(byte[] masterSecret, String uniqueInfo) throws Exception {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Assuming you need a 256-bit key. If you need keys of different sizes, adjust accordingly.
            return digest.digest((uniqueInfo + Arrays.toString(masterSecret)).getBytes());
        }
    }

    public static class CryptoUtils {

        public static class EncryptionUtil {

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

        public static class DecryptionUtil {

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

