import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
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
        keyfile = "keyfile.txt";
        File file = new File(keyfile);
        if (file.length() == 0) {
            firstTime = true;
        }
        else {
            firstTime = false;
        }
    }

    // Save keys to file
    public static void saveKeysToFile(String publicKey, String privateKey, String server_privatekey, String fileName) throws IOException {
        try (ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(fileName))) {
            outputStream.writeObject(publicKey);
            outputStream.writeObject(privateKey);
            outputStream.writeObject(server_privatekey);
        }
    }

    // Load keys from file
    public static KeyPair loadKeysFromFile(String fileName) throws IOException, ClassNotFoundException {
        try (ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(fileName))) {
            PublicKey publicKey = (PublicKey) inputStream.readObject();
            PrivateKey privateKey = (PrivateKey) inputStream.readObject();
            server_publickey = (PublicKey) inputStream.readObject();
            return new KeyPair(publicKey, privateKey);
        }
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
        String enc_msg = Arrays.toString(cryptoManager.encryptMessage(enc.getBytes(), (PublicKey) server_publickey));
        String final_msg = "login:" + username + ":" + enc_msg;

        out.println(final_msg);

        String server_msg = in.readLine();

        String final_server_msg = Arrays.toString(cryptoManager.decryptMessage(server_msg.getBytes(), (PrivateKey) keys.getPrivate()));

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
