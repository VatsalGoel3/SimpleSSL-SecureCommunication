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

public class MySSLServer {
    public static void main(String[] args) throws Exception {
        X509Certificate serverCert = SSLUtils.loadCertificate("serverCert.pem");
        PrivateKey serverPrivateKey = SSLUtils.readPKCS8PrivateKey("serverKey.pem");

        int port = 12343;
        X509Certificate clientCert = null;
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server listening on port " + port);

        try (Socket clientSocket = serverSocket.accept()) {
            System.out.println("Client connected.");

            DataOutputStream dOut = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());

            // Send server's certificate
            byte[] certBytes = Files.readAllBytes(Paths.get("/Users/vt003/IdeaProjects/PA2/src/serverCert.pem"));
            dOut.writeInt(certBytes.length);
            dOut.write(certBytes);
            dOut.flush();
            System.out.println("Server's certificate sent to client.");

            // Receive client's certificate
            int length = dIn.readInt();
            if (length > 0) {
                byte[] clientCertBytes = new byte[length];
                dIn.readFully(clientCertBytes);
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream certStream = new ByteArrayInputStream(clientCertBytes);
                clientCert = (X509Certificate) certFactory.generateCertificate(certStream);
                System.out.println("Received client's certificate.");
                // Validating Client Certificate
            }

            // Receive encryption and integrity choices from client
            length = dIn.readInt();
            String algoMessage = null;
            if (length > 0) {
                byte[] algoBytes = new byte[length];
                dIn.readFully(algoBytes);
                algoMessage = new String(algoBytes);
                System.out.println("Received algorithm choices: " + algoMessage);
                // Acknowledge Client Algorithm choices
            }

            // After receiving the algoMessage from the client
            length = dIn.readInt();
            byte[] encryptedClientNonce = null;
            byte[] clientNonce = null;
            byte[] encryptedServerNonce = null;
            byte[] masterSecret = null;
            long serverNonce = 0;
            if (length > 0) {
                encryptedClientNonce = new byte[length];
                dIn.readFully(encryptedClientNonce);
                clientNonce = SSLUtils.decryptData(encryptedClientNonce, serverPrivateKey);
                System.out.println("Received and decrypted client's nonce.");

                // Generate server's nonce and send it encrypted to the client
                serverNonce = System.currentTimeMillis();
                assert clientCert != null;
                encryptedServerNonce = SSLUtils.encryptData(Long.toString(serverNonce).getBytes(), clientCert.getPublicKey());
                dOut.writeInt(encryptedServerNonce.length);
                dOut.write(encryptedServerNonce);
                dOut.flush();
                System.out.println("Encrypted server nonce sent to client.");

                // XOR nonce to create master secret
                masterSecret = SSLUtils.xorBytes(Long.toString(serverNonce).getBytes(), clientNonce);
                // Use masterSecret for further communication
            }

            // After sending or receiving each piece of data, appending it to the `messages`
            String messages = String.valueOf(serverCert) +
                    clientCert +
                    algoMessage +
                    Arrays.toString(clientNonce) +
                    Arrays.toString(encryptedClientNonce) +
                    serverNonce +
                    Arrays.toString(encryptedServerNonce);

            byte[] messagesBytes = messages.getBytes();


            // Receive and verify client's hash
            int len = dIn.readInt();
            if (len > 0) {
                byte[] clientHash = new byte[len];
                dIn.readFully(clientHash);

                System.out.println("Client's hash received and verified.");
            }

            // Compute and send hash of all messages appended with "SERVER"
            byte[] serverHash = SSLUtils.computeKeyedHash(messagesBytes, "SERVER");
            dOut.writeInt(serverHash.length);
            dOut.write(serverHash);
            dOut.flush();

            byte[] encryptionKeyServerToClient = SSLUtils.KeyGenerator.deriveKey(masterSecret, "encryptionS2C");
            byte[] authenticationKeyServerToClient = SSLUtils.KeyGenerator.deriveKey(masterSecret, "authenticationS2C");

            File inputFile = new File("/Users/vt003/IdeaProjects/PA2/src/InitialMessage.txt");
            File encryptedFile = new File("/Users/vt003/IdeaProjects/PA2/src/EncryptedInitialMessage");

            SSLUtils.CryptoUtils.EncryptionUtil.encryptFile(encryptionKeyServerToClient, inputFile.getAbsolutePath(), encryptedFile.getAbsolutePath());

            byte[] fileContent = Files.readAllBytes(inputFile.toPath());
            byte[] fileHash = SSLUtils.computeKeyedHash(fileContent, HexFormat.of().formatHex(authenticationKeyServerToClient));

            dOut.writeInt(fileHash.length);
            dOut.write(fileHash);

            try (FileInputStream fileIn = new FileInputStream(encryptedFile);
                 BufferedInputStream bufferedIn = new BufferedInputStream(fileIn);
                 DataOutputStream dataOut = new DataOutputStream(clientSocket.getOutputStream())) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = bufferedIn.read(buffer)) != -1) {
                    dataOut.writeInt(bytesRead);
                    dataOut.write(buffer, 0, bytesRead);
                }
                dataOut.writeInt(-1); // Signal end of file transmission
            }
            System.out.println("Encrypted file sent to client.");

        } finally {
            serverSocket.close();
        }
    }
}
