package cs4351;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Random;
import java.util.Scanner;

public class EchoSeverSkeleton {
    public static void main(String[] args) {
        System.out.println("Connection to my sever has started");
        int sessionId = 0;

        try {
            ServerSocket serverSocket = new ServerSocket(8008);

            while (true) {
                Socket clients = serverSocket.accept();

                new ClientHandler(clients, ++sessionId).start();
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("Connection with my sever has ended");
    }

    private static class ClientHandler extends Thread {
        protected Socket socket;
        protected int id;

        public ClientHandler(Socket client, int id) {
            socket = client;
            this.id = id;
        }

        public void run() {
            Cipher cipherEnc;
            ObjectInputStream objectInput;
            ObjectOutputStream objectOutput;
            try {
                BufferedReader in
                        = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));
                PrintWriter out
                        = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream()));
                String messageFromClient = in.readLine();
                System.out.println("From Client: " + messageFromClient);

                try {
                    Scanner fileReader = new Scanner(new File("certificate.txt"));
                    String line = "";
                    while (!"-----END SIGNATURE-----".equals(line)) {
                        line = fileReader.nextLine();
                        out.println(line);
                        out.flush();
                    }
                    out.flush();
                } catch (FileNotFoundException e) {
                    System.out.println("problem sending the certificate to server");
                    return;
                }

                PublicKey[] pkpair = new PublicKey[2];
                try {
                    FileWriter fileWriter = new FileWriter("certificateFromClient.txt");
                    String line = "";
                    while (!"-----END SIGNATURE-----".equals(line)) {
                        line = in.readLine();
                        fileWriter.write(line);
                        fileWriter.write("\n");
                        fileWriter.flush();
                    }
                    fileWriter.close();
                    BufferedReader serverFile = new BufferedReader(new FileReader("certificateFromClient.txt"));
                    CertDetails certDetails = new CertDetails();
                    pkpair = VerifyCert.vCert(serverFile, certDetails);
                    System.out.println("Certificate Received from Client and Verified");
                } catch (IOException e) {
                    System.out.println("Error: " + e);
                    e.printStackTrace();
                }
                byte[] serverRandomBytes = new byte[8];
                objectOutput = new ObjectOutputStream(socket.getOutputStream()); // for writing objects to socket
                try {
                    new Random().nextBytes(serverRandomBytes);

                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, pkpair[0]);

                    byte[] encryptedBytes = cipher.doFinal(serverRandomBytes);
                    objectOutput.writeObject(encryptedBytes);
                    System.out.println("Random bytes sent to Client");

                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                    byte[] hashedRandom = messageDigest.digest(encryptedBytes);

                    PrivateKey privateKey = PemUtils.readPrivateKey
                            ("ServerKeys/ChristopherUrielServerDSAprivateKey.pem", "DSA");

                    byte[] hashedSignature = SignDSA.sign(privateKey, hashedRandom);
                    objectOutput.writeObject(hashedSignature);
                    System.out.println("Signature has been sent");

                } catch (IOException e) {
                    e.printStackTrace();
                }
                objectInput = new ObjectInputStream(socket.getInputStream());
                byte[] encryptedBytes = (byte[]) objectInput.readObject();

                byte[] signature = (byte[]) objectInput.readObject();

                PrivateKey privateKey = PemUtils.readPrivateKey(
                        "ServerKeys/ChristopherUrielServerRSAprivateKey.pem", "RSA");
                byte[] clientRandomBytes = DecryptRSA.decrypt(privateKey, encryptedBytes);
                System.out.println("Received and Decrypted Bytes from Client");

                byte[] sharedSecret = new byte[16];
                System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
                System.arraycopy(clientRandomBytes, 0, sharedSecret, 8, 8);

                cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");

                SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
                cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] iv = cipherEnc.getIV();
                objectOutput.writeObject(iv);

                byte[] clientIV = (byte[]) objectInput.readObject();
                Cipher cipherDC = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipherDC.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(clientIV));

                boolean done = false;
                while (!done) {
                    byte[] encryptedMessage = (byte[]) objectInput.readObject();
                    String message = new String(cipherDC.doFinal(encryptedMessage));
                    if (message.trim().equals("BYE")) {
                        done = true;
                    } else {
                        System.out.println("Message: " + message);

                        byte[] sendBack = cipherEnc.doFinal(message.getBytes());

                        objectOutput.writeObject(sendBack);
                        objectOutput.flush();
                    }
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                    IllegalBlockSizeException | BadPaddingException | IOException |
                    ClassNotFoundException | InvalidAlgorithmParameterException e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
            }
        }
    }
}

