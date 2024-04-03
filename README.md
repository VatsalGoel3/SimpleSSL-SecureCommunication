# Simplified SSL Implementation (SimpleSSL)

## Overview
This project implements a simplified version of the Secure Sockets Layer (SSL) protocol, termed mySSL, in Java. It demonstrates the core functionalities of SSL, including certificate-based authentication, secure key exchange, data encryption, and integrity verification. Designed for educational purposes, this project offers a hands-on approach to understanding how secure communication is established in a client-server model over an insecure network.

## Features
- **Certificate-based Authentication:** Utilizes self-signed X509 certificates for the authentication of the client and server.
- **Secure Key Exchange:** Implements a custom handshake mechanism for securely exchanging keys using RSA encryption.
- **Data Encryption and Integrity:** Supports data encryption and integrity checks using AES for encryption and HMAC-SHA256 for integrity verification.
- **Nonces for Master Secret Generation:** Utilizes nonces exchanged during the handshake phase, combined through XOR operation, to generate a master secret.

## Project Structure
The project consists of three main components:

1. **SimpleSSLServer.java:** The server component that listens for connections, performs the handshake, sends an encrypted file to the client, and verifies the integrity of the communication.

2. **SimpleSSLClient.java:** The client component that initiates the connection to the server, participates in the handshake, receives the encrypted file, decrypts it, and verifies its integrity.

3. **SSLUtils.java:** A utility class that provides cryptographic functionalities such as certificate loading, encryption/decryption, nonce generation, keyed hash computation, and key derivation.

## Getting Started
### Prerequisites
- Java Development Kit (JDK) 11 or later.
- Basic knowledge of SSL/TLS protocols and Java programming.

### Setup
1. Clone this repository to your local machine.
2. Generate self-signed X509 certificates for both the client and server. Place them in the project directory.
3. Ensure the paths to the certificates and private keys are correctly specified in `SimpleSSLServer.java` and `SimpleSSLClient.java`.

### Running the Project
1. Compile the Java files:
   ```
   javac SimpleSSLServer.java SimpleSSLClient.java SSLUtils.java
   ```
2. Start the server:
   ```
   java SimpleSSLServer
   ```
3. In a separate terminal, start the client:
   ```
   java SimpleSSLClient
   ```

## Implementation Details
### Handshake Phase
- **Certificate Exchange:** The client and server exchange their certificates.
- **Algorithm Agreement:** The client sends its encryption and integrity algorithm preferences to the server.
- **Nonce Exchange and Master Secret Generation:** Encrypted nonces are exchanged and used to generate a master secret.
- **Hash Verification:** Both parties compute and exchange hashes of the messages exchanged to verify integrity.

### Data Phase
- A file is encrypted using AES and sent from the server to the client along with a hash for integrity verification.
- The client decrypts the file and verifies its integrity by comparing the hash.

### Security Considerations
- This project is intended for educational purposes and should not be used in production environments.
- The use of self-signed certificates, while suitable for this project, would not be appropriate for real-world applications requiring a higher level of trust.

## Contributions
Contributions are welcome. Please submit a pull request or open an issue to suggest improvements or add new features.

## License
This project is licensed under the GPL v3 License - see the [LICENSE](LICENSE) file for details.

---

Remember to adjust paths, prerequisites, or any other specific details according to your project's actual structure and requirements.
