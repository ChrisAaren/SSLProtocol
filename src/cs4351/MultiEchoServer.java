package cs4351;
import java.io.*;
import java.net.*; 

public class MultiEchoServer {
 // This code was provided by Yoonsik Cheon at least 10 years ago.
 // It was modified several times by Luc Longpre over the years.
 // This version used for Computer Security, Spring 2019.    
    public static void main(String[] args) {
        System.out.println("MultiEchoServer started."); 
        int sessionID = 0;
    
        try {
            ServerSocket s = new ServerSocket(8008); 
            // The server runs until an error occurs
            // or is stopped externally
            for (;;) {
                Socket incoming = s.accept(); 
                // start a connection with the client
                // in a new thread and wait for another
                // connection
                new ClientHandler(incoming, ++sessionID).start();
                // start() causes the thread to begin execution
                // the JVM calls the run() method of this thread
            }
        } catch (Exception e) {
            System.out.println("Error: " + e); 
        }

        System.out.println("MultiEchoServer stopped."); 
    }

    private static class ClientHandler extends Thread {

        protected Socket incoming; 
        protected int id;

        public ClientHandler(Socket incoming, int id) {
            this.incoming = incoming;
            this.id = id;
        }

        public void run() {
            try {
                BufferedReader in 
                    = new BufferedReader(
                        new InputStreamReader(incoming.getInputStream())); 
                PrintWriter out 
                    = new PrintWriter(
                        new OutputStreamWriter(incoming.getOutputStream())); 
                out.print("Hello! This is Java MultiEchoServer. ");
                out.println("Enter BYE to exit."); 
                out.flush();
                // keep echoing the strings received until
                // receiving the string "BYE" which will break
                // out of the for loop and close the thread
                for (;;) {
                    String str = in.readLine(); 
                    if (str == null) {
                        break; 
                    } else {
                        out.println("Echo: " + str);
                        out.flush(); 
                        System.out.println("Received from session "+id+": "+ str);                       
                        if (str.trim().equals("BYE")) 
                            break; 
                    }
                }
                System.out.println("Session "+id+ " ended.");
                incoming.close(); 
            } catch (Exception e) {
                System.out.println("Error: " + e); 
            }
        }
    }
}
