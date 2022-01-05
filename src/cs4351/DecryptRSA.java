package cs4351;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.*;

class DecryptRSA {

    public static void main(String[] args) {
        // This program reads an RSA private key from a file
        // and an encrypted message, decrypts the message
        // and prints it.
        // Written by Luc Longpre for Computer Security, Spring 2019

        File file;
        PrivateKey privKey;
        Cipher cipher;
        byte[] decryptedByteArray;
        String encryptedString, decryptedString;

        // get the private key from file
        privKey = PemUtils.readPrivateKey("RSAprivateKey.pem","RSA");

        // get the encrypted Message
        try {
            file = new File("encryptedMessage.txt");
            Scanner input = new Scanner(file);
            encryptedString = input.nextLine();
            System.out.println("The encrypted string is: " + encryptedString);
        } catch (Exception e) {
            System.out.println("Could not open encryptedMessage file");
            return;
        }
        decryptedByteArray = decrypt(privKey, Base64.getDecoder().decode(encryptedString));
        decryptedString = new String(decryptedByteArray);
        System.out.println("The decrypted string is: " + decryptedString);
    }

    public static byte[] decrypt(PrivateKey privKey, byte[] encryptedByteArray) {
        // decrypts a byte array using a private key
        // and returns the decryption as a byte array
       
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            return cipher.doFinal(encryptedByteArray);      
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("error while decrypting the message");
            return null;
        }
    }
}
