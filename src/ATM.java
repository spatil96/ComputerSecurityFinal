import javax.crypto.*;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class ATM {
    private static SSLSocket socket;
    public static void main(String[] args) {

        if (args.length != 2) {
            System.out.println("Please enter in format as java ATM <bank_domain> <bank_port>");
            System.exit(1);
        }
        String serverDomain = args[0]; //taking input of remote.cs
        int serverPort = Integer.parseInt(args[1]); //port number which is same as server
        System.setProperty("javax.net.ssl.trustStore", "sumeet.jts");
        System.setProperty("javax.net.ssl.trustStorePassword", "123456");


        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
             socket =
                    (SSLSocket) factory.createSocket(serverDomain, serverPort);
            if (!socket.isConnected()) {
                System.out.println("Failed to connect to the server.");
                System.exit(1);
            }
            System.out.println("Connected to the server.");
            //Generating Secret key using AES
            SecretKey symKey = symKeyGen();
            System.out.println("symkey without encryption"+symKey.toString());
            //Encryt symKey Using public key
            Encrypt encrypt = new Encrypt();
            String encryptedSymKey = encrypt.encrytSymKey(
                    Base64.getEncoder().encodeToString(symKey.getEncoded()));
//            System.out.println("Printing encrptedSymKey:"+encryptedSymKey);
            // Prompt the user for ID and password
            while(true) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                System.out.print("Enter your ID: ");
                String userID = reader.readLine();
                System.out.print("Enter your password: ");
                String password = reader.readLine();
                //Encrypt id and password
                String idPassword = userID + "||" + password;
                String encryptedIdPassword = encrypt.encryptIdPassword(idPassword, symKey);
//            System.out.println("encrypted is and password"+encryptedIdPassword);
                // Send the ID and password to the server
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                out.println(encryptedSymKey);
                out.println(encryptedIdPassword);

                // Receive and print the server's response
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String response = in.readLine();
                System.out.println(response);
                //Logic to transfer money
                if (response.equalsIgnoreCase("ID and password are correct")) {
                    moneyTransferLogic(out, in, socket);

                }

//                socket.close();
            }
//            socket.close();
        } catch (IOException | NoSuchAlgorithmException e ) {
            e.printStackTrace();
            System.exit(1);
        } catch (IllegalBlockSizeException | NoSuchPaddingException |
                 InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }finally {
            try {
                // Close the socket outside the loop
               socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void moneyTransferLogic(PrintWriter out, BufferedReader in, SSLSocket socket) throws IOException {
        while(true){
        System.out.println("Please select one of the following actions (enter 1, 2, or 3):\n" +
                "1. Transfer money\n" +
                "2. Check account balance\n" +
                "3. Exit");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String userInput = reader.readLine();
            String res=null;
        switch (userInput) {
            case "1":
                while(true) {
                    System.out.println("Please select an account (enter 1 or 2):\n" +
                            "1. Savings\n" +
                            "2. Checking");
                    BufferedReader savingOrCheckingReader = new BufferedReader(new InputStreamReader(System.in));
                    String userInputForSavingOrChecking = savingOrCheckingReader.readLine();
                    if(userInputForSavingOrChecking.equalsIgnoreCase("1")||
                            userInputForSavingOrChecking.equalsIgnoreCase("2")){
                    //handleMoneyTransfer(out, in, socket);
                        System.out.println("Enter recipient’s ID");
                        String id = savingOrCheckingReader.readLine();
                        System.out.println("Enter amount");
                        String amount = savingOrCheckingReader.readLine();
                        out.println(userInputForSavingOrChecking+"||"+id+"||"+amount);
                        System.out.println(in.readLine());
                        break;
                    }
                    else{
                        System.out.println("incorrect input");
                    }

//                break;
                }
                break;
            case "2":
                out.println(userInput);
                String bal = in.readLine();
                System.out.println("bal---------"+bal);
                String[] parts = bal.split("\\|\\|");
                String saving = parts[0];
                String checking = parts[1];
                System.out.println("Your savings account balance:" + saving);
                System.out.println("Your checking account balance:" + checking);
                break;
            case "3":
                out.println(userInput);
                String response = in.readLine();
                if(response.equalsIgnoreCase("3")){
                System.out.println("Exiting. Goodbye!");
                out.close();
                in.close();
                socket.close();
                System.exit(1);
                }
            default:
                System.out.println("Incorrect input");
                break;
        }
        }
    }
    private static void handleMoneyTransfer(PrintWriter out, BufferedReader in, SSLSocket socket) throws IOException {
        // Server response for money transfer request
        String transferResponse = in.readLine();
        System.out.println(transferResponse);

        if (transferResponse.equalsIgnoreCase("Enter recipient's ID:")) {
            // Prompt user for recipient's ID and transfer amount
            System.out.print("Enter recipient's ID: ");
            String recipientID = in.readLine();
            out.println(recipientID);

            System.out.print("Enter transfer amount: ");
            String transferAmount = in.readLine();
            out.println(transferAmount);

            // Server response after processing money transfer request
            String transferResult = in.readLine();
            System.out.println(transferResult);
        }
    }

    private static SecretKey symKeyGen() throws NoSuchAlgorithmException {
        SecureRandom securerandom
                = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256,new SecureRandom());
        return keyGenerator.generateKey();
    }
}
