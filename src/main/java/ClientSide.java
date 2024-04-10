import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class ClientSide {
    private Socket clientSocket;
    private static Scanner scanner;
    private static PrintWriter out;
    private static BufferedReader in;
    private static boolean logged;
    private boolean firstTime;
    private static Key server_publickey;
    private static Key privatekey;
    private static Key publickey;
    private static String keyfile;
    private static String symkey;
    private static CryptoManager cryptoManager = new CryptoManager();
    private static String username;

    ClientSide(String serveradress, int port) throws IOException {
        this.scanner = new Scanner(System.in);
        clientSocket = new Socket(serveradress, port);
        out = new PrintWriter(clientSocket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        logged = false;
        keyfile = "src/main/java/keyfile.txt";
        File file = new File(keyfile);
        System.out.println("Size: " + file.length());
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

        printWriter.println(publicKey);
        printWriter.println(privateKey);
        printWriter.println(server_publickey);
        printWriter.close();
    }

    // Load keys from file
    public static KeyPair loadKeysFromFile(String fileName) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        File myObj = new File(fileName);
        Scanner myReader = new Scanner(myObj);
        String data = myReader.nextLine();
        byte[] keyBytes = Base64.getDecoder().decode(data);
        // Create a key specification object from the decoded bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        // Get a key factory instance for RSA
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // Generate the public key from the key specification
        publickey = keyFactory.generatePublic(keySpec);

        data = myReader.nextLine();
        byte[] keyBytes2 = Base64.getDecoder().decode(data);
        // Create a key specification object from the decoded bytes
        PKCS8EncodedKeySpec keySpec2 = new PKCS8EncodedKeySpec(keyBytes2);
        // Get a key factory instance for RSA
        KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
        // Generate the public key from the key specification
        privatekey = keyFactory2.generatePrivate(keySpec2);

        data = myReader.nextLine();
        byte[] keyBytes3 = Base64.getDecoder().decode(data);
        // Create a key specification object from the decoded bytes
        X509EncodedKeySpec keySpec3 = new X509EncodedKeySpec(keyBytes3);
        // Get a key factory instance for RSA
        KeyFactory keyFactory3 = KeyFactory.getInstance("RSA");
        // Generate the public key from the key specification
        server_publickey = keyFactory3.generatePublic(keySpec3);

        return new KeyPair((PublicKey) publickey, (PrivateKey) privatekey);
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
        System.out.println("2. Logout & Exit");
        System.out.print("Enter your choice: ");
    }

    private static boolean firstTimeLogin() throws IOException {
        System.out.println("Username: ");
        scanner.nextLine();
        username = scanner.nextLine();

        System.out.println("Symetric Key: ");
        //scanner.nextLine();
        //symkey = scanner.nextLine();

        symkey = "DWlTAyiwAht/wgJwfTL4CjWBkj7cOGPdd0dRk+q/lo4=";
        String enc = "firstlogin";
        String enc_msg = cryptoManager.encryptMessage(enc, symkey);
        String final_msg = "firstlogin:" + username + ":" + enc_msg;

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

        KeyPair keys = loadKeysFromFile(keyfile);

        String enc = "login";
        String enc_msg = cryptoManager.encryptMessage(enc, (PublicKey) server_publickey);
        String final_msg = "login:" + username + ":" + enc_msg;

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
        String final_msg = "op1:" + username + ":" + enc_msg;

        out.println(final_msg);

        String server_msg = in.readLine();


        String final_server_msg = cryptoManager.decryptMessage(server_msg, symkey);

        String[] elements = final_server_msg.split(":");


        if (!elements[0].equals("op1")) {
            return false;
        }

        int res = Integer.parseInt(elements[1]);

        System.out.println("Result from square root of " + number + " = " + res);

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

                if (choice == 2) {
                    if (!logout()) {
                        System.out.println("Something went wrong in logout");
                    }
                    break;
                }
                else {
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
            }
        }
    }

    public static void main(String[] args) throws Exception {
        ClientSide client = new ClientSide("127.0.0.1", 4422);
        client.start();
    }


}
