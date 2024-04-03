import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;

public class SimpleSSLClient {

    public static void main(String[] args) throws Exception {
        // Load the client's certificate and private key
        X509Certificate clientCert = SSLUtils.loadCertificate("clientCert.pem");
        PrivateKey clientPrivateKey = SSLUtils.readPKCS8PrivateKey("clientKey.pem");

        // Server information
        String host = "localhost";
        int port = 12343;

        // Establish a socket connection to the server
        try (Socket socket = new Socket(host, port)) {
            System.out.println("Connected to server at " + host + ":" + port);

            // Set up streams for communication
            DataInputStream dIn = new DataInputStream(socket.getInputStream());
            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());

            // Receive the server's certificate
            int length = dIn.readInt();
            byte[] serverCertBytes = new byte[length];
            dIn.readFully(serverCertBytes);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(serverCertBytes));
            System.out.println("Received server's certificate.");

            // Send the client's certificate to the server
            byte[] clientCertBytes = Files.readAllBytes(Paths.get("clientCert.pem"));
            dOut.writeInt(clientCertBytes.length);
            dOut.write(clientCertBytes);
            dOut.flush();
            System.out.println("Client's certificate sent to server.");

            // Send encryption and integrity choices to the server
            String algoMessage = "Encryption:RSA|Integrity:HmacSHA256;";
            byte[] algoBytes = algoMessage.getBytes();
            dOut.writeInt(algoBytes.length);
            dOut.write(algoBytes);
            dOut.flush();
            System.out.println("Encryption and integrity algorithms sent to server.");

            // Generate, encrypt, and send the client nonce
            long clientNonce = System.currentTimeMillis();
            byte[] encryptedClientNonce = SSLUtils.encryptData(Long.toString(clientNonce).getBytes(), serverCert.getPublicKey());
            dOut.writeInt(encryptedClientNonce.length);
            dOut.write(encryptedClientNonce);
            dOut.flush();
            System.out.println("Encrypted client nonce sent to server.");

            // Receive and decrypt the server's nonce
            length = dIn.readInt();
            byte[] encryptedServerNonce = new byte[length];
            dIn.readFully(encryptedServerNonce);
            byte[] serverNonce = SSLUtils.decryptData(encryptedServerNonce, clientPrivateKey);
            System.out.println("Received and decrypted server's nonce.");

            // Create master secret by XORing nonces
            byte[] masterSecret = SSLUtils.xorBytes(Long.toString(clientNonce).getBytes(), serverNonce);

            // Compute hash of the messages for integrity check and send it to the server
            String messages = serverCert + algoMessage + Arrays.toString(encryptedClientNonce) + Arrays.toString(serverNonce);
            byte[] clientHash = SSLUtils.computeKeyedHash(messages.getBytes(), "CLIENT");
            dOut.writeInt(clientHash.length);
            dOut.write(clientHash);
            dOut.flush();

            // Receive and verify the server's hash (dummy check for demonstration, real verification needed)
            length = dIn.readInt();
            byte[] serverHash = new byte[length];
            dIn.readFully(serverHash);
            // The real hash verification should be implemented here

            // Derive keys for encryption and authentication
            byte[] encryptionKey = SSLUtils.KeyGenerator.deriveKey(masterSecret, "encryption");
            byte[] authenticationKey = SSLUtils.KeyGenerator.deriveKey(masterSecret, "authentication");

            // Prepare to receive the encrypted file
            String receivedEncryptedFile = "EncryptedReceivedFile";
            String decryptedFile = "DecryptedReceivedFile.txt";

            // Receive file hash for integrity check
            length = dIn.readInt();
            byte[] receivedHash = new byte[length];
            dIn.readFully(receivedHash);
            System.out.println("Received file hash from server.");

            // Receive the encrypted file
            try (FileOutputStream fileOut = new FileOutputStream(receivedEncryptedFile);
                 BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOut)) {

                while ((length = dIn.readInt()) != -1) {
                    byte[] buffer = new byte[length];
                    dIn.readFully(buffer);
                    bufferedOut.write(buffer);
                }
            }
            System.out.println("Encrypted file received from server.");

            // Decrypt the received file
            SSLUtils.CryptoUtils.DecryptionUtil.decryptFile(encryptionKey, receivedEncryptedFile, decryptedFile);
            System.out.println("File decrypted.");

            // Perform integrity check on the decrypted file (dummy check, real verification needed)
            byte[] decryptedFileContent = Files.readAllBytes(Paths.get(decryptedFile));
            byte[] decryptedFileHash = SSLUtils.computeKeyedHash(decryptedFileContent, HexFormat.of().formatHex(authenticationKey));
            // The real integrity check should be implemented here
        }
    }
}
