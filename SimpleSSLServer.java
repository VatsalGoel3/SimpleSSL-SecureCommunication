import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;

public class SimpleSSLServer {
    public static void main(String[] args) throws Exception {
        // Load server certificate and private key for SSL communication
        X509Certificate serverCert = SSLUtils.loadCertificate("serverCert.pem");
        PrivateKey serverPrivateKey = SSLUtils.readPKCS8PrivateKey("serverKey.pem");

        // Setup server socket on specified port
        int port = 12343;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server listening on port " + port);

            // Accept connection from client
            try (Socket clientSocket = serverSocket.accept()) {
                System.out.println("Client connected.");

                // Setup input and output streams for data exchange
                DataOutputStream dOut = new DataOutputStream(clientSocket.getOutputStream());
                DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());

                // Send server's certificate to client
                byte[] certBytes = Files.readAllBytes(Paths.get("serverCert.pem"));
                dOut.writeInt(certBytes.length);
                dOut.write(certBytes);
                dOut.flush();
                System.out.println("Server's certificate sent to client.");

                // Receive and load client's certificate
                int length = dIn.readInt();
                if (length > 0) {
                    byte[] clientCertBytes = new byte[length];
                    dIn.readFully(clientCertBytes);
                    X509Certificate clientCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                                                    .generateCertificate(new ByteArrayInputStream(clientCertBytes));
                    System.out.println("Received client's certificate.");
                    // Client certificate can now be validated or used for encryption
                }

                // Receive client's encryption and integrity preferences
                length = dIn.readInt();
                String algoMessage = "";
                if (length > 0) {
                    byte[] algoBytes = new byte[length];
                    dIn.readFully(algoBytes);
                    algoMessage = new String(algoBytes);
                    System.out.println("Received algorithm choices: " + algoMessage);
                }

                // Process client's nonce, generate server's nonce, create master secret
                length = dIn.readInt();
                if (length > 0) {
                    byte[] encryptedClientNonce = new byte[length];
                    dIn.readFully(encryptedClientNonce);
                    byte[] clientNonce = SSLUtils.decryptData(encryptedClientNonce, serverPrivateKey);
                    System.out.println("Received and decrypted client's nonce.");

                    long serverNonce = System.currentTimeMillis();
                    byte[] encryptedServerNonce = SSLUtils.encryptData(Long.toString(serverNonce).getBytes(), SSLUtils.loadCertificate("clientCert.pem").getPublicKey());
                    dOut.writeInt(encryptedServerNonce.length);
                    dOut.write(encryptedServerNonce);
                    dOut.flush();
                    System.out.println("Encrypted server nonce sent to client.");

                    byte[] masterSecret = SSLUtils.xorBytes(Long.toString(serverNonce).getBytes(), clientNonce);
                }

                // Compute and send hash of all messages for integrity check
                // Note: Actual verification should be implemented here based on the real application requirements
                String messages = Arrays.toString(certBytes) + algoMessage; // Simplified example
                byte[] serverHash = SSLUtils.computeKeyedHash(messages.getBytes(), "SERVER");
                dOut.writeInt(serverHash.length);
                dOut.write(serverHash);
                dOut.flush();
                System.out.println("Server's hash sent to client.");

                // Encrypt and send a file to client
                // Note: For simplicity, the file path is hardcoded. Consider making it configurable.
                String filePath = "InitialMessage.txt"; // Example file path
                File inputFile = new File(filePath);
                byte[] encryptionKey = SSLUtils.KeyGenerator.deriveKey(masterSecret, "encryptionS2C");
                byte[] fileContent = Files.readAllBytes(inputFile.toPath());
                byte[] fileHash = SSLUtils.computeKeyedHash(fileContent, HexFormat.of().formatHex(encryptionKey));
                dOut.writeInt(fileHash.length);
                dOut.write(fileHash);

                // Encrypt and send the file content
                File encryptedFile = new File("Encrypted" + inputFile.getName());
                SSLUtils.CryptoUtils.EncryptionUtil.encryptFile(encryptionKey, inputFile.getAbsolutePath(), encryptedFile.getAbsolutePath());
                try (FileInputStream fileIn = new FileInputStream(encryptedFile)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = fileIn.read(buffer)) != -1) {
                        dOut.writeInt(bytesRead);
                        dOut.write(buffer, 0, bytesRead);
                    }
                }
                dOut.writeInt(-1); // Signal end of file transmission
                System.out.println("Encrypted file sent to client.");
            }
        }
    }
}
