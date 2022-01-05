package cs4351;
import java.io.*;
import java.net.*;
import java.util.Scanner;

public class EchoClient {
 // This code was provided by Yoonsik Cheon at least 10 years ago.
 // It was modified several times by Luc Longpre over the years.
 // This version used for Computer Security, Spring 2019.     
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
            BufferedReader in
                    = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            PrintWriter out
                    = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

            System.out.println("Starting messages to the server. Type messages, type BYE to end");
            boolean done = false;
            System.out.println(in.readLine());
            while (!done) {
                // Read message from the user
                String userStr = userInput.nextLine();
                // Send the message to the server
                out.println(userStr);
                out.flush();
                // If user says "BYE", end conversation
                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Get for reply from server,
                    // Print the server reply
                    System.out.println(in.readLine());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
