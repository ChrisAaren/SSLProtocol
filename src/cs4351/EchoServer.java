package cs4351;
import java.io.*;
import java.net.*; 

public class EchoServer {
 // This code originally was written from a piece of code written 
 // by Yoonsik Cheon at least 10 years ago.
 // It was rewritten several times by Luc Longpre over the years and
 // may have reached a state that has only little resemblance to the original code.
 // This version used for Computer Security, Spring 2019   

    public static void main(String[] args) {
        System.out.println("EchoServer started.");
        try {
            ServerSocket s = new ServerSocket(8008);
            while (true) {
                Socket incoming = s.accept();
                System.out.println("Connected to: "
                        + incoming.getInetAddress()
                        + " at port: " + incoming.getLocalPort());
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(incoming.getInputStream()));
                PrintWriter out = new PrintWriter(
                        new OutputStreamWriter(incoming.getOutputStream()));

                out.print("Hello! This is Java EchoServer. ");
                out.println("Enter BYE to exit.");
                out.flush();

                for (;;) {
                    String str = in.readLine();
                    if (str == null) {
                        break;
                    } else {
                        out.println("Echo: " + str);
                        out.flush();
                        System.out.println("Received: " + str);

                        if (str.trim().equals("BYE")) {
                            break;
                        }
                    }
                }
                incoming.close();
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("EchoServer stopped.");
    }
}
