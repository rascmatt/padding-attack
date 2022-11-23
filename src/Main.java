import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {

    private static final int BLOCK_SIZE_BYTE = 16;
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        /* Generate key */
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(BLOCK_SIZE_BYTE * 8);
        SecretKey key = keyGenerator.generateKey();

        /* Generate IV */
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec spec = new IvParameterSpec(iv);

        /* Define encryption algorithm */
        final Cipher enc = Cipher.getInstance(ALGORITHM);
        enc.init(Cipher.ENCRYPT_MODE, key, spec);

        /* Define decryption algorithm */
        final Cipher dec = Cipher.getInstance(ALGORITHM);
        dec.init(Cipher.DECRYPT_MODE, key, spec);

        final String message = "Matthias";
        final byte[] ciphertext = enc.doFinal(message.getBytes(StandardCharsets.UTF_8));

        System.out.println("Message:   " + message);
        System.out.println("M (hex):   " + bytesToHex(message.getBytes(StandardCharsets.UTF_8)));
        System.out.println("Encrypted: " + bytesToHex(ciphertext));

        byte[] result = PaddingAttack.attack(BLOCK_SIZE_BYTE, PaddingAttack.concat(iv, ciphertext), bytes -> {
            byte[] a_iv = Arrays.copyOfRange(bytes, 0, BLOCK_SIZE_BYTE);
            byte[] a_ciphertext = Arrays.copyOfRange(bytes, BLOCK_SIZE_BYTE, bytes.length);
            try
            {
                dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(a_iv));
                dec.doFinal(a_ciphertext);
                return false;
            } catch (BadPaddingException e)
            {
                return true;
            } catch (IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            }
        });

        System.out.println("Dec (hex): " + bytesToHex(result));
        final String s = new String(result, StandardCharsets.UTF_8);
        System.out.println("Decrypted: " + s);
    }

    public static String bytesToHex(byte[] bytes) {
        byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
        byte[] hexChars = new byte[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }
}