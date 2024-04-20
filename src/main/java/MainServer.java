import org.example.Main;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Dictionary;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Hashtable;

public class MainServer {

    private static PrivateKey private_key;
    private static PublicKey public_key;
    public static DatabaseManager database = new DatabaseManager("jdbc:sqlite:src/main/Database/database_server.db");
    public CryptoManager cryptoManager = new CryptoManager();
    private ServerSocket serverSocket;
    private static Dictionary<String, Integer> user_ports = new Hashtable<>();
    private static Dictionary<String, Integer> user_seqnum = new Hashtable<>();


    private static String convertKeyToString(Key key) {
        byte[] keyBytes = key.getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }
    public MainServer(int port) throws IOException, NoSuchAlgorithmException {
        KeyPair keyPair = cryptoManager.generateKeyPair();
        private_key = keyPair.getPrivate();
        public_key = keyPair.getPublic();
        serverSocket = new ServerSocket(port);
    }

    public void start() {
        System.out.println("Server started...");

        while (true) {
            try {
                // Accept incoming client connections
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected: " + clientSocket);

                // Start a new thread to handle each client
                ClientHandler clientHandler = new ClientHandler(clientSocket, cryptoManager, clientSocket.getPort());
                new Thread(clientHandler).start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;

        public CryptoManager cryptoManager;
        private PrintWriter out;
        private BufferedReader in;
        private int port;

        public ClientHandler(Socket socket, CryptoManager c, int port) {
            this.clientSocket = socket;
            cryptoManager = c;
            this.port = port;
        }

        public boolean firstlogin(String[] elements) throws NoSuchAlgorithmException {
            if (!database.isFirstTime(elements[1])) {
                return false;
            }

            String symkey = database.getSymetricKey(elements[1]);
            String dec_msg = cryptoManager.decryptMessage(elements[2], symkey);

            if (dec_msg.equals("firstlogin")) {
                String seq_msg = cryptoManager.decryptMessage(elements[3], symkey);
                user_seqnum.put(elements[1], Integer.valueOf(seq_msg));

                KeyPair keyPair = cryptoManager.generateKeyPair();

                byte[] keypub = keyPair.getPublic().getEncoded();
                String final_keypub = Base64.getEncoder().encodeToString(keypub);

                byte[] keypriv = keyPair.getPrivate().getEncoded();
                String final_keypriv = Base64.getEncoder().encodeToString(keypriv);

                byte[] keypub_server = public_key.getEncoded();
                String final_keypub_server = Base64.getEncoder().encodeToString(keypub_server);


                String msg_to_send = "firstlogin:" + final_keypub + ":" + final_keypriv + ":" + final_keypub_server;
                String final_msg = cryptoManager.encryptMessage(msg_to_send, symkey);
                database.registerUser(elements[1], final_keypub);
                database.changeFirstTime(elements[1]);
                database.changePrivilege(elements[1], 1);
                out.println(final_msg);
                return true;
            }
            return false;
        }

        public boolean logout(String[] elements) throws NoSuchAlgorithmException {
            if (database.isFirstTime(elements[1])) {
                return false;
            }

            String symkey = database.getSymetricKey(elements[1]);
            String dec_msg = cryptoManager.decryptMessage(elements[2], symkey);

            if (dec_msg.equals("logout")) {
                KeyPair keyPair = cryptoManager.generateKeyPair();
                String msg_to_send = "logout:ok";
                String final_msg = cryptoManager.encryptMessage(msg_to_send, symkey);
                database.endSession(elements[1]);
                out.println(final_msg);
                return true;
            }
            return false;
        }

        public boolean login(String[] elements) throws Exception {
            if (database.isFirstTime(elements[1])) {
                return false;
            }

            byte[] pubkey = Base64.getDecoder().decode(database.getPublicKey(elements[1]));
            String dec_msg = cryptoManager.decryptMessage(elements[2], private_key);

            if (dec_msg.equals("login")) {
                String seq_msg = cryptoManager.decryptMessage(elements[3], private_key);
                user_seqnum.put(elements[1], Integer.valueOf(seq_msg));

                String symkey = cryptoManager.generateSymmetricKey();
                String msg_to_send = "login:" + symkey;
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubkey);
                // Get a key factory instance for RSA
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                // Generate the public key from the key specification
                PublicKey final_publicKey = keyFactory.generatePublic(keySpec);
                String final_msg = cryptoManager.encryptMessage(msg_to_send, final_publicKey);

                database.startSession(elements[1], symkey);

                out.println(final_msg);
                return true;
            }
            return false;
        }

        public boolean op1(String[] elements) throws Exception {
            if (database.isFirstTime(elements[1])) {
                return false;
            }

            String symkey = database.getSymetricKey(elements[1]);
            String dec_msg = cryptoManager.decryptMessage(elements[2], symkey);
            Integer priv = database.getPrivilege(elements[1]);
            String seq_num = cryptoManager.decryptMessage(elements[3], symkey);

            if (Integer.parseInt(seq_num) != user_seqnum.get(elements[1])) {
                return false;
            }

            user_seqnum.put(elements[1], user_seqnum.get(elements[1]) + 1);

            if (priv < 1) {
                return false;
            }

            if (dec_msg.contains("op1")) {
                String[] op_elements = dec_msg.split(":");
                Integer res = (int) Math.sqrt(Integer.valueOf(op_elements[1]));
                String msg_to_send = "op1" + ":" + res + ":" + user_seqnum.get(elements[1]);
                user_seqnum.put(elements[1], user_seqnum.get(elements[1]) + 1);
                String final_msg = cryptoManager.encryptMessage(msg_to_send, symkey);
                out.println(final_msg);
                return true;
            }
            return false;
        }

        public boolean op2(String[] elements) throws Exception {
            if (database.isFirstTime(elements[1])) {
                return false;
            }

            String symkey = database.getSymetricKey(elements[1]);
            String dec_msg = cryptoManager.decryptMessage(elements[2], symkey);
            Integer priv = database.getPrivilege(elements[1]);
            String seq_num = cryptoManager.decryptMessage(elements[3], symkey);

            if (Integer.parseInt(seq_num) != user_seqnum.get(elements[1])) {
                return false;
            }

            user_seqnum.put(elements[1], user_seqnum.get(elements[1]) + 1);

            if (priv < 2) {
                return false;
            }

            if (dec_msg.contains("op2")) {
                String[] op_elements = dec_msg.split(":");
                Integer res = (int) Math.cbrt(Integer.valueOf(op_elements[1]));
                System.out.println("RES: " + res);
                String msg_to_send = "op2" + ":" + res + ":" + user_seqnum.get(elements[1]);
                user_seqnum.put(elements[1], user_seqnum.get(elements[1]) + 1);
                String final_msg = cryptoManager.encryptMessage(msg_to_send, symkey);
                out.println(final_msg);
                return true;
            }
            return false;
        }

        public boolean op3(String[] elements) throws Exception {
            if (database.isFirstTime(elements[1])) {
                return false;
            }

            String symkey = database.getSymetricKey(elements[1]);
            String dec_msg = cryptoManager.decryptMessage(elements[2], symkey);
            Integer priv = database.getPrivilege(elements[1]);
            String seq_num = cryptoManager.decryptMessage(elements[3], symkey);

            if (Integer.parseInt(seq_num) != user_seqnum.get(elements[1])) {
                return false;
            }

            user_seqnum.put(elements[1], user_seqnum.get(elements[1]) + 1);

            if (priv < 3) {
                return false;
            }

            if (dec_msg.contains("op3")) {
                String[] op_elements = dec_msg.split(":");
                float n = 1.0f / Integer.parseInt(op_elements[2]);
                int res = (int) Math.pow(Integer.valueOf(op_elements[1]), n);
                String msg_to_send = "op3" + ":" + res + ":" + user_seqnum.get(elements[1]);
                user_seqnum.put(elements[1], user_seqnum.get(elements[1]) + 1);
                String final_msg = cryptoManager.encryptMessage(msg_to_send, symkey);
                out.println(final_msg);
                return true;
            }
            return false;
        }

        public boolean getPubKey(String[] elements) throws Exception {
            if (database.isFirstTime(elements[1])) {
                return false;
            }

            String symkey = database.getSymetricKey(elements[1]);
            String dec_msg = cryptoManager.decryptMessage(elements[2], symkey);
            Integer priv = database.getPrivilege(elements[1]);
            String seq_num = cryptoManager.decryptMessage(elements[3], symkey);

            if (Integer.parseInt(seq_num) != user_seqnum.get(elements[1])) {
                return false;
            }

            user_seqnum.put(elements[1], user_seqnum.get(elements[1]) + 1);

            if (priv < 1) {
                return false;
            }

            if (dec_msg.contains("getpubkey")) {
                String[] op_elements = dec_msg.split(":");
                System.out.println("TESTE:" + user_ports);
                String msg_to_send = "getpubkey" + ":" + database.getPublicKey(op_elements[1]) + ":" + user_ports.get(op_elements[1]);
                user_seqnum.put(elements[1], user_seqnum.get(elements[1]) + 1);
                String final_msg = cryptoManager.encryptMessage(msg_to_send, symkey);
                out.println(final_msg);
                return true;
            }
            return false;
        }

        @Override
        public void run() {
            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                while (true) {
                    String msg = in.readLine();
                    String[] elements = msg.split(":");
                    System.out.println(msg);

                    if (elements[0].equals("firstlogin")) {
                        if (!firstlogin(elements)) {
                            out.println("Forbidden!");
                        }
                        else {
                            String symkey = database.getSymetricKey(elements[1]);
                            String ok = cryptoManager.decryptMessage(in.readLine(), symkey);
                            user_ports.put(elements[1], port);
                            if (ok.equals("ok")) {
                                //database.endSession(elements[1]);
                                continue;
                            }
                        }
                    }
                    else if (elements[0].equals("login")) {
                        if (!login(elements)) {
                            out.println("Forbidden!");
                        }
                        else {
                            String symkey = database.getSymetricKey(elements[1]);
                            String ok = cryptoManager.decryptMessage(in.readLine(), symkey);
                            user_ports.put(elements[1], port);
                            if (ok.equals("ok")) {
                                continue;
                            }
                        }
                    }
                    else if (elements[0].equals("op1")) {
                        if (!op1(elements)) {
                            out.println("Forbidden!");
                        }
                        else {
                            String symkey = database.getSymetricKey(elements[1]);
                            String ok = cryptoManager.decryptMessage(in.readLine(), symkey);
                            if (ok.equals("ok")) {
                                continue;
                            }
                        }
                    }
                    else if (elements[0].equals("op2")) {
                        if (!op2(elements)) {
                            out.println("Forbidden!");
                        }
                        else {
                            String symkey = database.getSymetricKey(elements[1]);
                            String ok = cryptoManager.decryptMessage(in.readLine(), symkey);
                            if (ok.equals("ok")) {
                                continue;
                            }
                        }
                    }
                    else if (elements[0].equals("op3")) {
                        if (!op3(elements)) {
                            out.println("Forbidden!");
                        }
                        else {
                            String symkey = database.getSymetricKey(elements[1]);
                            String ok = cryptoManager.decryptMessage(in.readLine(), symkey);
                            if (ok.equals("ok")) {
                                continue;
                            }
                        }
                    }
                    else if (elements[0].equals("getpubkey")) {
                        if (!getPubKey(elements)) {
                            out.println("Forbidden!");
                        }
                        else {
                            String symkey = database.getSymetricKey(elements[1]);
                            String ok = cryptoManager.decryptMessage(in.readLine(), symkey);
                            if (ok.equals("ok")) {
                                continue;
                            }
                        }
                    }
                    else if (elements[0].equals("logout")) {
                        if (!logout(elements)) {
                            out.println("Forbidden!");
                        }
                        else {
                            user_ports.remove(elements[1]);
                            user_seqnum.remove(elements[1]);
                            break;
                        }
                    }

                }

                // Close resources
                in.close();
                out.close();
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static void main(String[] args) {
        int port = 4422;
        try {
            MainServer server = new MainServer(port);
            server.start();
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


}
