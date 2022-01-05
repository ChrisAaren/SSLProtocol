package cs4351;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class EchoClientSkeleton {
    // This code includes socket code originally provided
    // by Dr. Yoonsik Cheon at least 10 years ago.
    // This version used for Computer Security, Spring 2019.    
    public static void main(String[] args) {

//        String host = "localhost";
//        String host = "cspl000.utep.edu";
        String host = "10.91.41.12";
//        String host = args[0];
        BufferedReader in;
        PrintWriter out;
        ObjectInputStream objectInput;
        ObjectOutputStream objectOutput;
        Cipher cipheRSA, cipherEnc;
        byte[] clientRandomBytes;
        PublicKey[] pkpair;
        Socket socket;
        try {
            socket = new Socket(host, 8008);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
        } catch (IOException e) {
            System.out.println("socket initialization error");
            return;
        }
        out.println("hello");
        out.flush();

        try {
            FileWriter fileWriter = new FileWriter("certificateFromServer.txt");
            String line = "";
            while (!"-----END SIGNATURE-----".equals(line)) {
                line = in.readLine();
                fileWriter.write(line);
                fileWriter.write("\n");
                fileWriter.flush();
            }
            fileWriter.close();
            BufferedReader serverFile = new BufferedReader(new FileReader("certificateFromServer.txt"));
            CertDetails certDetails = new CertDetails();
            pkpair = VerifyCert.vCert(serverFile, certDetails);

            if (pkpair == null) {
                System.out.println("Certificate was not verified");
            } else {
                System.out.println("Certificate is verified");
            }
        } catch (IOException e) {
            System.out.println("problem reading the certificate from server");
            return;
        }

        try {
            File file = new File("certificate.txt");
            Scanner input = new Scanner(file);
            String line;
            while (input.hasNextLine()) {
                line = input.nextLine();
                out.println(line);
            }
            out.flush();
        } catch (FileNotFoundException e) {
            System.out.println("certificate file not found");
            return;
        }
        byte[] fromServerRandomBytes;
        try {
            objectOutput = new ObjectOutputStream(socket.getOutputStream());
            objectInput = new ObjectInputStream(socket.getInputStream());

            byte[] encryptedBytes = (byte[]) objectInput.readObject();
            byte[] signatureBytes = (byte[]) objectInput.readObject();

            PrivateKey privateKey = PemUtils.readPrivateKey
                    ("ServerKeys/ChristopherUrielServerRSAprivateKey.pem", "RSA");

            fromServerRandomBytes = DecryptRSA.decrypt(privateKey, encryptedBytes);
            System.out.println("Random Bytes Decrypted from Server");
        } catch (IOException |
                ClassNotFoundException ex) {
            ex.printStackTrace();
            System.out.println("Problem with receiving random bytes from server");
            return;
        }
        clientRandomBytes = new byte[8];
        new Random().nextBytes(clientRandomBytes);
        try {
            PublicKey serverPublicKey = PemUtils.readPublicKey(
                    "ServerKeys/ChristopherUrielServerRSApublicKey.pem", "RSA");
            byte[] encryptedBytes = EncryptRSA.encrypt(pkpair[0], clientRandomBytes);

            objectOutput.writeObject(encryptedBytes);
            PrivateKey privateKey = PemUtils.readPrivateKey(
                    "ClientKeys/ChristopherUrielClientDSAprivateKey.pem", "DSA");

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hashedRandom = messageDigest.digest(clientRandomBytes);
            byte[] signatureBytes = SignDSA.sign(privateKey, hashedRandom);
            objectOutput.writeObject(signatureBytes);

        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("error computing or sending the signature for random bytes");
            return;
        }
        byte[] sharedSecret = new byte[16];
        System.arraycopy(fromServerRandomBytes, 0, sharedSecret, 0, 8);
        System.arraycopy(clientRandomBytes, 0, sharedSecret, 8, 8);
        try {
            cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipherEnc.getIV();
            objectOutput.writeObject(iv);
        } catch (IOException | NoSuchAlgorithmException
                | NoSuchPaddingException |
                InvalidKeyException e) {
            System.out.println("error setting up the AES encryption");
            return;
        }
        try {
            byte[] serverIv = (byte[]) objectInput.readObject();
            SecretKey secretKey = new SecretKeySpec(sharedSecret, "AES");
            Cipher cipherDC = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherDC.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(serverIv));
            System.out.println("Starting messages to the server. Type messages, type BYE to end");
            Scanner userInput = new Scanner(System.in);
            boolean done = false;
            while (!done) {
                String userStr = userInput.nextLine();
                byte[] encryptedBytes = cipherEnc.doFinal(userStr.getBytes());
                objectOutput.writeObject(encryptedBytes);
                objectOutput.flush();
                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    encryptedBytes = (byte[]) objectInput.readObject();
                    String message = new String(cipherDC.doFinal(encryptedBytes));
                    System.out.println("Message: " + message);
                }
            }
        } catch (IllegalBlockSizeException | BadPaddingException | IOException | ClassNotFoundException |
                InvalidKeyException | InvalidAlgorithmParameterException |
                NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("error in encrypted communication with server");
        }
    }
}
