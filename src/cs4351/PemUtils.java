package cs4351;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class PemUtils {
    // This class contains 4 static methods to write and read
    // RSA public and private keys.
    // The PEM format uses Base64 encoding, which is available since Java 8.
    // Written by Luc Longpre for Computer Security, Spring 2019  

    static void writePublicKey(PublicKey pubKey, String fileName)
            throws FileNotFoundException {
        File file = new File(fileName);
        // The new java construct, try with resource ...
        try (PrintWriter fw = new PrintWriter(file)) {
            fw.println("-----BEGIN PUBLIC KEY-----");
            String keyStr = Base64.getEncoder().encodeToString(pubKey.getEncoded());
            // Separating at 64 characters per line is not necessary,
            // but is more readable
            for (int i = 0; i < keyStr.length(); i += 64) {
                fw.println(keyStr.substring(i, Integer.min(keyStr.length(), i + 64)));
            }
            fw.println("-----END PUBLIC KEY-----");
            fw.close();
        }
    }

    static PublicKey readPublicKey(String fileName, String algorithm) {
        File file;
        String contents = "";
        PublicKey pKey = null;
        try {
            file = new File(fileName);
            Scanner input = new Scanner(file);
            String line = input.nextLine();
            if (!"-----BEGIN PUBLIC KEY-----".equals(line)) {
                System.out.println("expecting:-----BEGIN PUBLIC KEY-----");
                System.out.println("got:" + line);
            } else {
                line = input.nextLine();
                while (!"-----END PUBLIC KEY-----".equals(line)) {
                    contents += line;
                    line = input.nextLine();
                }
            }
            input.close();
        } catch (Exception e) {
            System.out.println("Could not open key file");
            return null;
        }
        byte[] keyBytes = Base64.getDecoder().decode(contents);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            pKey = kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("public key recovery exception");
            return null;
        }
        return pKey;
    }

    static PublicKey constructPublicKey(String pubKeyString, String algorithm) {
        String contents = "";
        PublicKey pKey = null;
        try {
            Scanner input = new Scanner(pubKeyString);
            String line = input.nextLine();
            if (!"-----BEGIN PUBLIC KEY-----".equals(line)) {
                System.out.println("expecting:-----BEGIN PUBLIC KEY-----");
                System.out.println("got:" + line);
            } else {
                line = input.nextLine();
                while (!"-----END PUBLIC KEY-----".equals(line)) {
                    contents += line;
                    line = input.nextLine();
                }
            }
            input.close();
        } catch (Exception e) {
            System.out.println("Could not open key file");
            return null;
        }
        byte[] keyBytes = Base64.getDecoder().decode(contents);
        X509EncodedKeySpec spec
                = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            pKey = kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("public key recovery exception");
            return null;
        }
        return pKey;
    }

    static void writePrivateKey(PrivateKey pubKey, String fileName)
            throws FileNotFoundException {
        File file = new File(fileName);
        PrintWriter fw = new PrintWriter(file);
        fw.println("-----BEGIN PRIVATE KEY-----");
        String keyStr = Base64.getEncoder().encodeToString(pubKey.getEncoded());
        // Separating at 64 characters per line is not necessary,
        // but is more readable
        for (int i = 0; i < keyStr.length(); i += 64) {
            fw.println(keyStr.substring(i, Integer.min(keyStr.length(), i + 64)));
        }
        fw.println("-----END PRIVATE KEY-----");
        fw.close();
    }

    static PrivateKey readPrivateKey(String fileName, String algorithm) {
        File file;
        String contents = "";
        PrivateKey prKey = null;
        try {
            file = new File(fileName);
            Scanner input = new Scanner(file);
            String line = input.nextLine();
            if (!"-----BEGIN PRIVATE KEY-----".equals(line)) {
                System.out.println("File format error");
            } else {
                line = input.nextLine();
                while (!"-----END PRIVATE KEY-----".equals(line)) {
                    contents += line;
                    line = input.nextLine();
                }
            }
            input.close();
        } catch (Exception e) {
            System.out.println("Could not open file");
        }
        byte[] keyBytes = Base64.getDecoder().decode(contents);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            prKey = kf.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println(e);
        }
        return prKey;
    }
}
