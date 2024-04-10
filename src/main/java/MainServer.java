import org.example.Main;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class MainServer {

    private static PrivateKey private_key;
    private static PublicKey public_key;
    public static DatabaseManager database = new DatabaseManager("jdbc:sqlite:src/main/Database/database_server.db");
    public CryptoManager cryptoManager = new CryptoManager();
    private ServerSocket serverSocket;


    private static String convertKeyToString(Key key) {
        byte[] keyBytes = key.getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }
    public MainServer(int port) throws IOException, NoSuchAlgorithmException {
        KeyPair keyPair = cryptoManager.generateKeyPair();
        private_key = keyPair.getPrivate();
        public_key = keyPair.getPublic();

        String test = "test";
        String sym = "DWlTAyiwAht/wgJwfTL4CjWBkj7cOGPdd0dRk+q/lo4=";
        String test_enc = cryptoManager.encryptMessage(test, sym);
        String test_dec = cryptoManager.decryptMessage(test_enc, sym);

        System.out.println("Test String: " + test);
        System.out.println("Symetric Key: " + sym);
        System.out.println("Encrypted Test String: " + test_enc);
        System.out.println("Decrypted Test String: " + test_dec);

        database.deleteUser("edu");


        System.out.println("Symetric Key:" + cryptoManager.generateSymmetricKey());

        database.addUser("edu", "DWlTAyiwAht/wgJwfTL4CjWBkj7cOGPdd0dRk+q/lo4=");

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
                ClientHandler clientHandler = new ClientHandler(clientSocket, cryptoManager);
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

        public ClientHandler(Socket socket, CryptoManager c) {
            this.clientSocket = socket;
            cryptoManager = c;

        }

        public boolean firstlogin(String[] elements) throws NoSuchAlgorithmException {
            if (!database.isFirstTime(elements[1])) {
                return false;
            }

            String symkey = database.getSymetricKey(elements[1]);
            String dec_msg = cryptoManager.decryptMessage(elements[2], symkey);

            if (dec_msg.equals("firstlogin")) {
                KeyPair keyPair = cryptoManager.generateKeyPair();
                String msg_to_send = "firstlogin:" + keyPair.getPublic() + ":" + keyPair.getPrivate() + ":" + public_key;
                String final_msg = cryptoManager.encryptMessage(msg_to_send, symkey);
                database.registerUser(elements[1], String.valueOf(keyPair.getPublic()));
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

            String pubkey = database.getPlublicKey(elements[1]);
            String dec_msg = Arrays.toString(cryptoManager.decryptMessage(elements[2].getBytes(), private_key));

            if (dec_msg.equals("login")) {
                String symkey = cryptoManager.generateSymmetricKey();
                String msg_to_send = "login:" + ":" + symkey;
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubkey.getBytes());
                // Get a key factory instance for RSA
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                // Generate the public key from the key specification
                PublicKey final_publicKey = keyFactory.generatePublic(keySpec);
                byte[] final_msg = cryptoManager.encryptMessage(msg_to_send.getBytes(), final_publicKey);

                database.startSession(elements[1], symkey);

                out.println(Arrays.toString(final_msg));
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

            if (priv < 1) {
                return false;
            }

            if (dec_msg.contains("op1")) {
                String[] op_elements = dec_msg.split(":");
                Integer res = (int) Math.sqrt(Integer.valueOf(op_elements[1]));
                String msg_to_send = "op1" + ":" + res;
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
                    else if (elements[0].equals("logout")) {
                        if (!logout(elements)) {
                            out.println("Forbidden!");
                        }
                        else {
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
