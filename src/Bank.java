import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Bank {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Please enter in format as java Bank <bank_port>");
            System.exit(1);
        }
        int port = Integer.parseInt(args[0]);//Port number between 1024 and 65535 --add check for this.
        System.setProperty("javax.net.ssl.keyStore", "sumeet.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "123456");

        SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

        try (SSLServerSocket serverSocket = (SSLServerSocket)factory.createServerSocket(port)) {
            System.out.println("Server started on port " + port);

            while (true) {
                try (SSLSocket clientSocket = (SSLSocket)serverSocket.accept()) {
                    handleClient(clientSocket);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(SSLSocket clientSocket) throws IOException {
        while(true) {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

                // Read data from the client (e.g., ID and password)
                String encryptedSymKey = in.readLine();

                String encryptedIdPassword = in.readLine();


                // Reading encryptedSymKey
                String decryptedSymKey = decryptSymmetricKey(encryptedSymKey);


                // Converting decryptedSymKey to SecretKey format for ease of decoding ID and Password
                SecretKey symKey = new SecretKeySpec(Base64.getDecoder().decode(decryptedSymKey), "AES");
                Cipher cipher = Cipher.getInstance("AES");

                // Decrypting ID and password
                String decryptedIdPassword = decryptIdPassword(encryptedIdPassword, symKey);
                System.out.println("Received ID and password: " + decryptedIdPassword);

                if (idPasswordMatch(decryptedIdPassword)) {
                    out.println("ID and password are correct");
                    // After this, we wait for the selection from the user
                    boolean exit = false;
                    while (true) {
                        String selection = in.readLine();
//                    System.out.println("");
                        String inp = selection;
                        switch (selection) {
                            case "2":
                                handleAccountBalance(in, out, decryptedIdPassword);
                                break;
                            case "3":
                                out.println("3");
                                exit = true;
                                break;
                            default:
                                System.out.println("from default");
                                handleMoneyTransfer(symKey, inp, out, decryptedIdPassword);

                                break;
                        }
                        if (exit) {
                            break;
                        }
                    }
                } else {
                    out.println("ID or password is incorrect. Please try again.");
                }
            } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
                     InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static void handleMoneyTransfer(SecretKey symKey, String in, PrintWriter out, String decryptedIdPassword) throws IOException {
        System.out.println("Hello");
       // System.out.println("in the line"+in.readLine());
        String[] idParts = in.split("\\|\\|");
        String accountType = idParts[0];
        String userIdRecipient = idParts[1];
        int amount = Integer.parseInt(idParts[2]);
        System.out.println("accountType"+accountType+"userIdrec"+userIdRecipient);
        String[] idMain = decryptedIdPassword.split("\\|\\|");
        String userIdMain = idMain[0];

        try (BufferedReader fileReader = new BufferedReader(new FileReader("balance.txt"))
        ) {
            StringBuilder updatedBalance = new StringBuilder();
            StringBuilder updatedBalance2 = new StringBuilder();
            String line;
            boolean recipientExists = false;

            while ((line = fileReader.readLine()) != null) {
                String[] parts = line.split(" ");
                String user = parts[0];
                System.out.println("user"+user);
                int savingInBal = Integer.parseInt(parts[1]);
                int checkInBal = Integer.parseInt(parts[2]);


                if (user.equals(userIdMain)) {
                    // Deduct the transfer amount from the sender's balance
                    if (accountType.equalsIgnoreCase("1")) {
                        if (savingInBal < amount) {
                            out.println("Your account does not have enough funds");
                            return;
                        }
                        int newSavingBalance = savingInBal - amount;
                        updatedBalance.append(user).append(" ").append(newSavingBalance).append(" ").append(checkInBal).append(System.lineSeparator());
                    } else if (accountType.equalsIgnoreCase("2")) {
                        if (checkInBal < amount) {
                            out.println("Your account does not have enough funds");
                            return;
                        }
                        int newCheckingBalance = checkInBal - amount;
                        updatedBalance.append(user).append(" ").append(savingInBal).append(" ").append(newCheckingBalance).append(System.lineSeparator());
                    }
                }
                else {
                    updatedBalance.append(line).append(System.lineSeparator());
                }
                //updatedBalance.append("\n");
            }
//            if (recipientExists) {
                // Write the updated balances back to the file
                try (PrintWriter writer = new PrintWriter(new FileWriter("balance.txt"))) {
                    writer.write(updatedBalance.toString());
//                    out.println("your transaction is successful");
                }
            updatedBalance = new StringBuilder();

            BufferedReader fileReader2 = new BufferedReader(new FileReader("balance.txt"));
            while ((line = fileReader2.readLine()) != null) {
                String[] parts = line.split(" ");
                String user = parts[0];
                int savingInBal = Integer.parseInt(parts[1]);
                int checkInBal = Integer.parseInt(parts[2]);

                if (user.equals(userIdRecipient)) {
                    // Recipient's ID exists
                    recipientExists = true;

                    // Update the recipient's balance
                    if (accountType.equalsIgnoreCase("1")) {
                        int newSavingBalance = savingInBal + amount;
                        updatedBalance.append(user).append(" ").append(newSavingBalance).append(" ").append(checkInBal).append(System.lineSeparator());
                    } else if (accountType.equalsIgnoreCase("2")) {
                        int newCheckingBalance = checkInBal + amount;
                        updatedBalance.append(user).append(" ").append(savingInBal).append(" ").append(newCheckingBalance).append(System.lineSeparator());
                    }
                    //updatedBalance.append("\n");
                }else {
                    updatedBalance.append(line).append(System.lineSeparator());
                }

            }



            if (recipientExists) {
                // Write the updated balances back to the file
                try (PrintWriter writer = new PrintWriter(new FileWriter("balance.txt"))) {
                    writer.write(updatedBalance.toString());
                    out.println("your transaction is successful");
                }
            } else {
                // The recipient's ID does not exist
                out.println("the recipient’s ID does not exist");
            }
        }
    }


    private static void handleAccountBalance(BufferedReader in, PrintWriter out, String decryptedIdPassword) throws IOException {
        String[] idMain = decryptedIdPassword.split("\\|\\|");
        String userIdMain = idMain[0];
        try (BufferedReader fileReader = new BufferedReader(new FileReader("balance.txt"))) {
            String line;
            while ((line = fileReader.readLine()) != null) {
                String[] parts = line.split(" ");
                String user = parts[0];
                String saving = parts[1];
                String checking = parts[2];
                String[] id = decryptedIdPassword.split("\\|\\|");
                if (user.equalsIgnoreCase(userIdMain)) {
                    out.println(saving+"||"+checking);
                    //return;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean idPasswordMatch(String decryptedIdPassword) {
        try (BufferedReader fileReader = new BufferedReader(new FileReader("password.txt"))) {
            String line;
            while ((line = fileReader.readLine()) != null) {
                String[] parts = line.split(" ");
                String id = parts[0];
                String pwd = parts[1];
                String idPwd = id+"||"+pwd;
                System.out.println("while decrypting idpwd"+idPwd);
                if (decryptedIdPassword.equalsIgnoreCase(idPwd)) {
                    // Correct ID and password
//                    out.println("“Correct ID and password");
                    return true;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }
    private static String decryptIdPassword(String encryptedIdPassword, SecretKey symKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, symKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedIdPassword));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static String decryptSymmetricKey(String encryptedSymKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeySpecException, IOException {
        // Read private key from file
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get("privateKey"));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        // Decrypt symmetric key using private key
        Cipher cipher = Cipher.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedSymKey));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

}

