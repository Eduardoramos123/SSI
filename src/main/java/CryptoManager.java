import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class CryptoManager {

    CryptoManager() {
    }

    public static String generateSymmetricKey() {
        try {
            // Create a KeyGenerator instance for AES (symmetric key algorithm)
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

            // Initialize the KeyGenerator with the desired key size (in bits)
            keyGenerator.init(256); // You can choose different key sizes as per your requirement

            // Generate the symmetric key
            SecretKey symmetricKey = keyGenerator.generateKey();

            // Convert the symmetric key to Base64 string
            byte[] keyBytes = symmetricKey.getEncoded();
            String symmetricKeyString = Base64.getEncoder().encodeToString(keyBytes);

            return symmetricKeyString;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String encryptMessage(String message, String symmetricKeyString) {
        try {
            // Decode symmetric key from Base64 string
            byte[] keyBytes = Base64.getDecoder().decode(symmetricKeyString);
            SecretKey symmetricKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");

            // Create Cipher instance for AES in CBC mode with PKCS5Padding
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);

            // Encrypt the message
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());

            // Convert encrypted bytes to Base64 string
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);

            return encryptedMessage;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            e.printStackTrace();
        }
        return "";
    }


    public static String decryptMessage(String encryptedMessage, String symmetricKeyString) {
        try {
            // Decode symmetric key from Base64 string
            byte[] keyBytes = Base64.getDecoder().decode(symmetricKeyString);
            SecretKey symmetricKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");

            // Create Cipher instance for AES in CBC mode with PKCS5Padding
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);

            // Decrypt the message
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));

            // Convert decrypted bytes to string
            String decryptedMessage = new String(decryptedBytes);

            return decryptedMessage;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes(StandardCharsets.UTF_8)));
    }

    public static String decryptMessage(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)), StandardCharsets.UTF_8);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        // Create a KeyPairGenerator instance for RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        // Initialize the KeyPairGenerator with a key size
        keyPairGenerator.initialize(2048);

        // Generate the key pair
        return keyPairGenerator.generateKeyPair();
    }

    public static int generateRandomNumber() {
        SecureRandom secureRandom = new SecureRandom();
        int randomNumber = secureRandom.nextInt(10_000_000) + 1;
        return randomNumber;
    }

}
