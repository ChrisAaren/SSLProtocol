package cs4351;

import java.io.*;
import java.util.Random;

public class CreateRandomSecret {

    public static void main(String[] args) {
        // This program creates random byte array for cryptographic use
        // and saves it in java object format to a file named randomBytes,
        // Written by Luc Longpre for Computer Security, Fall 2019.
        try {
            FileOutputStream fos = new FileOutputStream("randomBytes");
            byte[] b = new byte[16];
            new Random().nextBytes(b);
            fos.write(b);
            fos.close();
        } catch (Exception e) {
            System.out.println("Problem creating file");
        }
    }
}
