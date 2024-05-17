import org.jasypt.util.text.BasicTextEncryptor;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import static java.lang.System.exit;

public class ClientSide {
    private static Socket clientSocket;
    private static Scanner scanner;
    private static PrintWriter out;
    private static BufferedReader in;
    private static boolean logged;
    private boolean firstTime;
    private static Key server_publickey;
    private static Key privatekey;
    private static Key publickey;
    private static String keyfile;
    private static String msgfile;
    private static String symkey;
    private static CryptoManager cryptoManager = new CryptoManager();
    private static String username;
    private static String password;
    private static int seq_number;
    private static PublicKey collaborator_pubkey;
    private static int collaborator_port;
    private static String collaborator_username;

    ClientSide(String serveradress, int port) throws IOException {
        this.scanner = new Scanner(System.in);
        clientSocket = new Socket(serveradress, port);
        out = new PrintWriter(clientSocket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        logged = false;
        keyfile = "src/main/java/keyfile2.txt";
        msgfile = "src/main/java/msgfile2.txt";
        File file = new File(keyfile);
        System.out.println("Size: " + file.length());
        seq_number = cryptoManager.generateRandomNumber();
        if (file.length() == 0) {
            firstTime = true;
        }
        else {
            firstTime = false;
        }
    }

    // Save keys to file
    public static void saveKeysToFile(String publicKey, String privateKey, String server_publickey, String fileName) throws IOException {
        FileWriter fileWriter = new FileWriter(fileName);
        PrintWriter printWriter = new PrintWriter(fileWriter);

        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        textEncryptor.setPassword(password);

        printWriter.println(textEncryptor.encrypt(publicKey));
        printWriter.println(textEncryptor.encrypt(privateKey));
        printWriter.println(textEncryptor.encrypt(server_publickey));


        //printWriter.println(publicKey);
        //printWriter.println(privateKey);
        //printWriter.println(server_publickey);
        printWriter.close();
    }

    // Load keys from file
    public static KeyPair loadKeysFromFile(String fileName) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        File myObj = new File(fileName);
        Scanner myReader = new Scanner(myObj);
        //String data = myReader.nextLine();

        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        textEncryptor.setPassword(password);


        String data = textEncryptor.decrypt(myReader.nextLine());
        byte[] keyBytes = Base64.getDecoder().decode(data);
        // Create a key specification object from the decoded bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        // Get a key factory instance for RSA
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // Generate the public key from the key specification
        publickey = keyFactory.generatePublic(keySpec);

        data = textEncryptor.decrypt(myReader.nextLine());
        byte[] keyBytes2 = Base64.getDecoder().decode(data);
        // Create a key specification object from the decoded bytes
        PKCS8EncodedKeySpec keySpec2 = new PKCS8EncodedKeySpec(keyBytes2);
        // Get a key factory instance for RSA
        KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
        // Generate the public key from the key specification
        privatekey = keyFactory2.generatePrivate(keySpec2);

        data = textEncryptor.decrypt(myReader.nextLine());
        byte[] keyBytes3 = Base64.getDecoder().decode(data);
        // Create a key specification object from the decoded bytes
        X509EncodedKeySpec keySpec3 = new X509EncodedKeySpec(keyBytes3);
        // Get a key factory instance for RSA
        KeyFactory keyFactory3 = KeyFactory.getInstance("RSA");
        // Generate the public key from the key specification
        server_publickey = keyFactory3.generatePublic(keySpec3);

        return new KeyPair((PublicKey) publickey, (PrivateKey) privatekey);
    }

    public static void saveMsgToFile(String msg, String signed, String user, String fileName) throws IOException {
        FileWriter fileWriter = new FileWriter(fileName, true);
        PrintWriter printWriter = new PrintWriter(fileWriter);

        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        textEncryptor.setPassword(password);

        printWriter.println(textEncryptor.encrypt(user));
        printWriter.println(textEncryptor.encrypt(msg));
        printWriter.println(textEncryptor.encrypt(signed));

        printWriter.close();
    }

    public static void readMsgFromFile(String fileName) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;

        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        textEncryptor.setPassword(password);

        System.out.println("\n");
        System.out.println("\n");
        System.out.println("\n");
        System.out.println("Message File:");

        while ((line = reader.readLine()) != null) {
            // Decrypt the line using the same password
            String decryptedLine = textEncryptor.decrypt(line);
            // Output the decrypted line
            System.out.println(decryptedLine);
        }

        reader.close();
    }

    private static void displayMenu1() {
        System.out.println("\n");
        System.out.println("1. First Time Login");
        System.out.println("2. Exit");
        System.out.print("Enter your choice: ");
    }

    private static void displayMenu2() {
        System.out.println("\n");
        System.out.println("1. Login");
        System.out.println("2. Exit");
        System.out.print("Enter your choice: ");
    }

    private static void displayMenu3() {
        System.out.println("\n");
        System.out.println("1. op1");
        System.out.println("2. op2");
        System.out.println("3. op3");
        System.out.println("4. send msg");
        System.out.println("5. Logout & Exit");
        System.out.print("Enter your choice: ");
    }

    private static boolean firstTimeLogin() throws IOException {
        System.out.println("Username: ");
        scanner.nextLine();
        username = scanner.nextLine();

        System.out.println("Symetric Key: ");
        //scanner.nextLine();
        symkey = scanner.nextLine().trim();

        System.out.println("Set Password: ");
        //scanner.nextLine();
        password = scanner.nextLine().trim();


        String enc = "firstlogin";
        String enc_msg = cryptoManager.encryptMessage(enc, symkey);
        String seq_msg = cryptoManager.encryptMessage(String.valueOf(seq_number), symkey);
        String final_msg = "firstlogin:" + username + ":" + enc_msg + ":" + seq_msg;

        System.out.println("Msg: " + final_msg);

        out.println(final_msg);

        String server_msg = in.readLine();

        String final_server_msg = cryptoManager.decryptMessage(server_msg, symkey);

        String[] elements = final_server_msg.split(":");

        if (!elements[0].equals("firstlogin")) {
            return false;
        }

        saveKeysToFile(elements[1], elements[2], elements[3], keyfile);

        logged = true;

        out.println("ok");

        return true;
    }

    private static boolean login() throws Exception {
        System.out.println("Username: ");
        scanner.nextLine();
        username = scanner.nextLine();
        System.out.println("Password: ");
        //scanner.nextLine();
        password = scanner.nextLine().trim();

        KeyPair keys = loadKeysFromFile(keyfile);

        String enc = "login";
        String enc_msg = cryptoManager.encryptMessage(enc, (PublicKey) server_publickey);
        String seq_msg = cryptoManager.encryptMessage(String.valueOf(seq_number), (PublicKey) server_publickey);
        String final_msg = "login:" + username + ":" + enc_msg + ":" + seq_msg;

        out.println(final_msg);

        String server_msg = in.readLine();

        String final_server_msg = cryptoManager.decryptMessage(server_msg, (PrivateKey) keys.getPrivate());

        System.out.println("Msg received: " + final_server_msg);

        String[] elements = final_server_msg.split(":");


        if (!elements[0].equals("login")) {
            return false;
        }

        symkey = elements[1];

        logged = true;

        out.println("ok");

        return true;
    }

    private static boolean op1(int number) throws Exception {
        String enc = "op1:" + number;
        String enc_msg = cryptoManager.encryptMessage(enc, symkey);
        String seq_msg = cryptoManager.encryptMessage(String.valueOf(seq_number), symkey);
        String final_msg = "op1:" + username + ":" + enc_msg + ":" + seq_msg;
        seq_number = seq_number + 1;

        out.println(final_msg);

        String server_msg = in.readLine();

        if (server_msg.contains("Forbidden")) {
            return false;
        }

        String final_server_msg = cryptoManager.decryptMessage(server_msg, symkey);

        String[] elements = final_server_msg.split(":");

        if (Integer.parseInt(elements[2]) != seq_number) {
            return false;
        }
        seq_number = seq_number + 1;


        if (!elements[0].equals("op1")) {
            return false;
        }

        int res = Integer.parseInt(elements[1]);

        System.out.println("Result from square root of " + number + " = " + res);

        out.println("ok");

        return true;
    }
    private static boolean op2(int number) throws Exception {
        String enc = "op2:" + number;
        String enc_msg = cryptoManager.encryptMessage(enc, symkey);
        String seq_msg = cryptoManager.encryptMessage(String.valueOf(seq_number), symkey);
        String final_msg = "op2:" + username + ":" + enc_msg + ":" + seq_msg;
        seq_number = seq_number + 1;

        out.println(final_msg);

        String server_msg = in.readLine();

        if (server_msg.contains("Forbidden")) {
            return false;
        }

        String final_server_msg = cryptoManager.decryptMessage(server_msg, symkey);

        String[] elements = final_server_msg.split(":");

        if (Integer.parseInt(elements[2]) != seq_number) {
            return false;
        }
        seq_number = seq_number + 1;


        if (!elements[0].equals("op2")) {
            return false;
        }

        int res = Integer.parseInt(elements[1]);

        System.out.println("Result from cubic root of " + number + " = " + res);

        out.println("ok");

        return true;
    }
    private static boolean op3(int number1, int number2) throws Exception {
        String enc = "op3:" + number1 + ":" + number2;
        String enc_msg = cryptoManager.encryptMessage(enc, symkey);
        String seq_msg = cryptoManager.encryptMessage(String.valueOf(seq_number), symkey);
        String final_msg = "op3:" + username + ":" + enc_msg + ":" + seq_msg;
        seq_number = seq_number + 1;

        out.println(final_msg);

        String server_msg = in.readLine();

        if (server_msg.contains("Forbidden")) {
            return false;
        }

        String final_server_msg = cryptoManager.decryptMessage(server_msg, symkey);

        String[] elements = final_server_msg.split(":");

        if (Integer.parseInt(elements[2]) != seq_number) {
            return false;
        }
        seq_number = seq_number + 1;


        if (!elements[0].equals("op3")) {
            return false;
        }

        int res = Integer.parseInt(elements[1]);

        System.out.println("Result from " + number2 + " root of " + number1 + " = " + res);

        out.println("ok");

        return true;
    }

    private static boolean logout() throws Exception {
        String enc = "logout";
        String enc_msg = cryptoManager.encryptMessage(enc, symkey);
        String final_msg = "logout:" + username + ":" + enc_msg;

        out.println(final_msg);

        String server_msg = in.readLine();


        String final_server_msg = cryptoManager.decryptMessage(server_msg, symkey);

        String[] elements = final_server_msg.split(":");


        if (!elements[0].equals("logout")) {
            return false;
        }

        if (elements[1].equals("ok")) {
            return true;
        }
        return false;
    }

    private static boolean getPubKey(String colaborator) throws Exception {
        String enc = "getpubkey:" + colaborator;
        String enc_msg = cryptoManager.encryptMessage(enc, symkey);
        String seq_msg = cryptoManager.encryptMessage(String.valueOf(seq_number), symkey);
        String final_msg = "getpubkey:" + username + ":" + enc_msg + ":" + seq_msg;
        seq_number = seq_number + 1;

        out.println(final_msg);

        String server_msg = in.readLine();


        String final_server_msg = cryptoManager.decryptMessage(server_msg, symkey);

        String[] elements = final_server_msg.split(":");


        if (!elements[0].equals("getpubkey")) {
            return false;
        }

        System.out.println("Public key: " + elements[1]);

        byte[] keyBytes = Base64.getDecoder().decode(elements[1]);
        // Create a key specification object from the decoded bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        // Get a key factory instance for RSA
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // Generate the public key from the key specification
        collaborator_pubkey = keyFactory.generatePublic(keySpec);
        collaborator_port = Integer.parseInt(elements[2]);

        out.println("ok");

        return true;
    }

    private static boolean message(String msg, PrintWriter new_out, BufferedReader new_in) throws Exception {
        String signed_msg = cryptoManager.signMessage(msg, (PrivateKey) privatekey);
        String enc = "msg:" + username + ":" + msg;
        String enc_msg = cryptoManager.encryptMessage(enc, collaborator_pubkey);
        //String enc_sign = cryptoManager.encryptMessage(signed_msg, collaborator_pubkey);

        //String seq_msg = cryptoManager.encryptMessage(String.valueOf(seq_number), collaborator_pubkey);
        //seq_number = seq_number + 1;

        new_out.println(enc_msg);
        new_out.println(signed_msg);

        String server_msg = new_in.readLine();


        String final_server_msg = cryptoManager.decryptMessage(server_msg, (PrivateKey) privatekey);

        String[] elements = final_server_msg.split(":");


        if (!elements[0].equals("ok")) {
            return false;
        }

        return true;
    }

    private static boolean respond(String elements, PrintWriter new_out, BufferedReader new_in) throws Exception {
        String dec_msg = cryptoManager.decryptMessage(elements, (PrivateKey) privatekey);

        String[] msg_elements = dec_msg.split(":");

        if (!msg_elements[0].equals("msg")) {
            return false;
        }

        if (!getPubKey(msg_elements[1])) {
            return false;
        }

        //String signed = cryptoManager.decryptMessage(new_in.readLine(), (PrivateKey) privatekey);
        String signed = new_in.readLine();

        if (!cryptoManager.verifySignature(msg_elements[2], signed, collaborator_pubkey)) {
            return false;
        }

        System.out.println("MSG from " + msg_elements[1] + ": " + msg_elements[2]);

        saveMsgToFile(msg_elements[2], signed, msg_elements[1], msgfile);

        //TODO: add a different seq num
        String ack = "ok:1234";
        String enc_ack = cryptoManager.encryptMessage(ack, collaborator_pubkey);

        new_out.println(enc_ack);

        return false;
    }

    private static boolean sending_message(String col_username, String msg) throws Exception {
        if (!getPubKey(col_username)) {
            return false;
        }

        System.out.println("HERE1 " + collaborator_port);
        Socket col_socket = new Socket("127.0.0.1", collaborator_port + 1);

        PrintWriter sendng_out = new PrintWriter(col_socket.getOutputStream(), true);
        BufferedReader sending_in = new BufferedReader(new InputStreamReader(col_socket.getInputStream()));


        if (!message(msg, sendng_out, sending_in)) {
            return false;
        }

        return true;
    }


    private static int getUserChoice() {
        return scanner.nextInt();
    }
    public void start() throws Exception {
        System.out.println("Client started...");

        while (true) {
            if (firstTime) {
                displayMenu1();
                int choice = getUserChoice();

                if (choice == 2) {
                    break;
                }
                else {
                    if(firstTimeLogin()) {
                        firstTime = false;
                        continue;
                    }
                    else {
                        System.out.println("Something went wrong in first login");
                        continue;
                    }
                }
            }
            else if (!logged && !firstTime) {
                displayMenu2();
                int choice = getUserChoice();

                if (choice == 2) {
                    break;
                }
                else {
                    if(login()) {
                        continue;
                    }
                    else {
                        System.out.println("Something went wrong in login");
                        continue;
                    }
                }
            }
            else if (logged && !firstTime) {
                displayMenu3();
                int choice = getUserChoice();

                if (choice == 5) {
                    if (!logout()) {
                        System.out.println("Something went wrong in logout");
                    }
                    break;
                }
                else if (choice == 1) {
                    System.out.println("Operation 1 Selected!");
                    System.out.println("Please write a int: ");
                    int num = scanner.nextInt();
                    if(op1(num)) {
                        continue;
                    }
                    else {
                        System.out.println("Something went wrong in op1");
                        continue;
                    }
                }
                else if (choice == 2) {
                    System.out.println("Operation 2 Selected!");
                    System.out.println("Please write a int: ");
                    int num = scanner.nextInt();
                    if(op2(num)) {
                        continue;
                    }
                    else {
                        System.out.println("Something went wrong in op2");
                        continue;
                    }
                }
                else if (choice == 3) {
                    System.out.println("Operation 3 Selected!");
                    System.out.println("Please write num1: ");
                    int num1 = scanner.nextInt();
                    System.out.println("Please write num2: ");
                    int num2 = scanner.nextInt();
                    if(op3(num1, num2)) {
                        continue;
                    }
                    else {
                        System.out.println("Something went wrong in op3");
                        continue;
                    }
                }
                else if (choice == 4) {
                    System.out.println("Sending Message!");
                    System.out.println("Please write user to send msg to: ");
                    scanner.nextLine();
                    String collaborator_user = scanner.nextLine();
                    System.out.println("Please write msg to send: ");
                    String msg = scanner.nextLine();
                    if(sending_message(collaborator_user, msg)) {
                        continue;
                    }
                    else {
                        System.out.println("Something went wrong in sending a message");
                        continue;
                    }
                }
            }
        }
    }

    public static void listen_handler(PrintWriter new_out, BufferedReader new_in) throws Exception {
        String msg_received = new_in.readLine();

        respond(msg_received, new_out, new_in);
    }

    public static void listen() throws IOException {

        //System.out.println("PORT: " + clientSocket.getLocalPort());
        ServerSocket serverSocket = new ServerSocket(clientSocket.getLocalPort() + 1);



        while (true) {
            try {
                // Accept incoming client connections
                Socket listenSocket = serverSocket.accept();
                System.out.println("Collaborator connected: " + listenSocket);

                PrintWriter listen_out = new PrintWriter(listenSocket.getOutputStream(), true);
                BufferedReader listen_in = new BufferedReader(new InputStreamReader(listenSocket.getInputStream()));


                // Start a new thread to handle each client

                Thread handlerThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            listen_handler(listen_out, listen_in);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
                handlerThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        ClientSide client = new ClientSide("127.0.0.1", 4422);

        Thread listenThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    listen();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        listenThread.start();


        client.start();
        exit(0);
    }


}
