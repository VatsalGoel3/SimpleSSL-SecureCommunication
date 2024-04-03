import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;

public class MySSLClient {
    public static void main(String[] args) throws Exception {
        X509Certificate clientCert = SSLUtils.loadCertificate("clientCert.pem");
        PrivateKey clientPrivateKey = SSLUtils.readPKCS8PrivateKey("clientKey.pem");

        String host = "localhost";
        int port = 12343;
        X509Certificate serverCert = null;
        try (Socket socket = new Socket(host, port)) {
            System.out.println("Connected to server at " + host + ":" + port);

            DataInputStream dIn = new DataInputStream(socket.getInputStream());
            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());

            // Receive server's certificate
            int length = dIn.readInt();
            if (length > 0) {
                byte[] serverCertBytes = new byte[length];
                dIn.readFully(serverCertBytes);
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream certStream = new ByteArrayInputStream(serverCertBytes);
                serverCert = (X509Certificate) certFactory.generateCertificate(certStream);
                System.out.println("Received server's certificate.");
            }

            // Send client's certificate to server
            byte[] clientCertBytes = Files.readAllBytes(Paths.get("clientCert.pem"));
            dOut.writeInt(clientCertBytes.length);
            dOut.write(clientCertBytes);
            dOut.flush();
            System.out.println("Client's certificate sent to server.");

            // Send encryption and integrity choices to server
            String algoMessage = "Encryption:RSA|Integrity:HmacSHA256;";
            byte[] algoBytes = algoMessage.getBytes();
            dOut.writeInt(algoBytes.length);
            dOut.write(algoBytes);
            dOut.flush();
            System.out.println("Encryption and integrity algorithms sent to server.");

            long clientNonce = System.currentTimeMillis();
            byte[] encryptedClientNonce = SSLUtils.encryptData(Long.toString(clientNonce).getBytes(), serverCert.getPublicKey());
            dOut.writeInt(encryptedClientNonce.length);
            dOut.write(encryptedClientNonce);
            dOut.flush();
            System.out.println("Encrypted client nonce sent to server.");

            // Receive and decrypt the server's nonce
            length = dIn.readInt();
            byte[] serverNonce = null;
            byte[] encryptedServerNonce = null;
            byte[] masterSecret = null;
            if (length > 0) {
                encryptedServerNonce = new byte[length];
                dIn.readFully(encryptedServerNonce);
                serverNonce = SSLUtils.decryptData(encryptedServerNonce, clientPrivateKey);
                System.out.println("Received and decrypted server's nonce.");

                // XOR nonce to create master secret
                masterSecret = SSLUtils.xorBytes(Long.toString(clientNonce).getBytes(), serverNonce);
            }

            // After sending or receiving each piece of data, appending it to the `messages`
            String messages = String.valueOf(serverCert) +
                    clientCert +
                    algoMessage +
                    clientNonce +
                    Arrays.toString(encryptedClientNonce) +
                    Arrays.toString(serverNonce) +
                    Arrays.toString(encryptedServerNonce);

            // Convert the accumulated messages into a byte array for hashing
            byte[] messagesBytes = messages.getBytes();

            // Compute and send hash of all messages appended with "CLIENT"
            byte[] clientHash = SSLUtils.computeKeyedHash(messagesBytes, "CLIENT");
            dOut.writeInt(clientHash.length);
            dOut.write(clientHash);
            dOut.flush();

            // Receive and verify server's hash
            length = dIn.readInt();
            if (length > 0) {
                byte[] serverHash = new byte[length];
                dIn.readFully(serverHash);
                if (clientHash == serverHash){
                    // Here, you would verify the server's hash for integrity
                    System.out.println("Server's hash received and verified.");
                }
            }
            byte[] encryptionKeyClientToServer = SSLUtils.KeyGenerator.deriveKey(masterSecret, "encryptionS2C");
            byte[] authenticationKeyClientToServer = SSLUtils.KeyGenerator.deriveKey(masterSecret, "authenticationS2C");

            String receivedEncryptedFile = "/Users/vt003/IdeaProjects/PA2/src/EncryptedReceivedFile";
            String decryptedFile = "/Users/vt003/IdeaProjects/PA2/src/DecryptedReceivedFile.txt";

            length = dIn.readInt();
            byte[] receivedHash = new byte[length];
            dIn.readFully(receivedHash);
            System.out.println("Received file hash from server.");

            // Receive the encrypted file
            try (DataInputStream dataIn = new DataInputStream(socket.getInputStream());
                 FileOutputStream fileOut = new FileOutputStream(receivedEncryptedFile);
                 BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOut)) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = dataIn.readInt()) != -1) {
                    if (bytesRead > 0) {
                        dataIn.readFully(buffer, 0, bytesRead);
                        bufferedOut.write(buffer, 0, bytesRead);
                    } else {
                        break; // End of file transmission
                    }
                }
            }
            System.out.println("Encrypted file received from server.");

            // Decrypt the file
            SSLUtils.CryptoUtils.DecryptionUtil.decryptFile(encryptionKeyClientToServer, receivedEncryptedFile, decryptedFile);
            System.out.println("File decrypted.");

            // After decryption, read the decrypted file content
            byte[] decryptedFileContent = Files.readAllBytes(Paths.get(decryptedFile));
            byte[] decryptedFileHash = SSLUtils.computeKeyedHash(decryptedFileContent, HexFormat.of().formatHex(authenticationKeyClientToServer));

            // Compare the hashes to verify file integrity
            if (Arrays.equals(receivedHash, decryptedFileHash)) {
                System.out.println("File integrity verified.");
            } else {
                System.out.println("File integrity verification failed.");
            }
        }

    }
}

