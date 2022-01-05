package cs4351;

import java.io.*;
import java.net.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoEchoClient {
 // The MultiEchoServer was provided by Yoonsik Cheon at least 10 years ago.
 // It was modified several times by Luc Longpre over the years.
 // This version is augmented by encrypting messages using AES encryption.
 // Used for Computer Security, Spring 2019.    
    public static void main(String[] args) {

        String host;
        Scanner userInput = new Scanner(System.in);
        if (args.length > 0) {
            host = args[0];
        } else {
            System.out.println("Enter the server's address: (IP address or \"localhost\")");
            host = userInput.nextLine();
        }
        try {
            Socket socket = new Socket(host, 8008);
            // in and out for socket communication using strings
            BufferedReader in
                    = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            System.out.println(in.readLine());
            PrintWriter out
                    = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            // We could use Base64 encoding and communicate with strings using in and out
            // However, we show here how to send and receive serializable java objects
            ObjectOutputStream objectOutput = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream objectInput = new ObjectInputStream(socket.getInputStream());
            // read the file of random bytes from which we can derive an AES key
            byte[] randomBytes;
            try {
                FileInputStream fis = new FileInputStream("randomBytes");
                randomBytes = new byte[fis.available()];
                System.out.println(randomBytes.length);
            } catch (Exception e) {
                System.out.println("problem reading the randomBytes file");
                return;
            }
            // we will use AES encryption, CBC chaining and PCS5 block padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // generate an AES key derived from randomBytes array
            SecretKeySpec secretKey = new SecretKeySpec(randomBytes, "AES");                
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            // the initialization vector was generated randomly
            // transmit the initialization vector to the server
            // no need to encrypt the initialization vector
            // send the vector as an object
            byte[] iv = cipher.getIV();           
            objectOutput.writeObject(iv); 
            
            System.out.println("Starting messages to the server. Type messages, type BYE to end");            
            boolean done = false;
            while (!done) {
                // Read message from the user
                String userStr = userInput.nextLine();
                // Encrypt the message
                byte[] encryptedByte = cipher.doFinal(userStr.getBytes());
                // Send encrypted message as an object to the server
                objectOutput.writeObject(encryptedByte);
                // If user says "BYE", end session
                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Receive the reply from the server and print it
                    // You need to modify this to handle encrypted reply
                    System.out.println(in.readLine());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
