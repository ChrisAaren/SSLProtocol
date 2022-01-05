package cs4351;
import java.io.*;
import java.security.*;

public class CreatePemDSAKeys {

    public static void main(String[] args) {
        // This program creates an DSA key pair,
        // saves the private key in a file in PEM format named privateKey.pem,
        // saves the public key in a file named publickey.pem.
        // The program uses PemUtils.java.
        // The PemUtils.java uses Base64 encoding, which is available since Java 8.
        // Written by Luc Longpre for Computer Security, Spring 2019

        File file;
        KeyPair key;

        // generate key pair
        try {
            // Initialize a key pair generator
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA","SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(1024,random);
            // Generate a key pair
            key = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            // If no provider supports RSA, or the key size is not supported
            System.out.println("Key pair generator failed to generate keys, " + e);
            return;
        }

        PrivateKey privKey = key.getPrivate();
        PublicKey pubKey = key.getPublic();

        try {
            PemUtils.writePublicKey(pubKey, "ChristopherUrielClientDSApublicKey.pem");
        } catch (FileNotFoundException e) {
            System.out.println("Write Public Key: File not found Exception");
        }

        try {
            PemUtils.writePrivateKey(privKey, "ChristopherUrielClientDSAprivateKey.pem");
        } catch (FileNotFoundException e) {
            System.out.println("Write Private Key: File not found Exception");
        }
    }
}
