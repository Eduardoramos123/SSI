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
import java.util.Arrays;
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

    public static String signMessage(String message, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA512withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verifySignature(String message, String signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("SHA512withRSA");
            sig.initVerify(publicKey);
            sig.update(message.getBytes());
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return sig.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static String generateOneTimeCode() {
        final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        final int LENGTH = 12;
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(LENGTH);
        for (int i = 0; i < LENGTH; i++) {
            int index = random.nextInt(CHARACTERS.length());
            sb.append(CHARACTERS.charAt(index));
        }
        return sb.toString();
    }

    public static String generateSymFromOneTimeCode(String code) {
        try {
            // Generate a secure random salt
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] keyB = sha256.digest(code.getBytes(StandardCharsets.UTF_8));

            // Ensure the key is exactly 256 bits (32 bytes) long
            keyB = Arrays.copyOf(keyB, 32);
            // Generate the key bytes


            // Create a SecretKeySpec for AES
            SecretKeySpec secretKey = new SecretKeySpec(keyB, "AES");

            // Encode the key in Base64
            String symmetricKeyString = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            return symmetricKeyString;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
