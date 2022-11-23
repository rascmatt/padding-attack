import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

public class PaddingAttack {

    /**
     * Execute a padding attack on a given ciphertext.
     *
     * @param blockSize The block size
     * @param ciphertext The ciphertext starting with the IV
     * @param oracle Returns true if the decryption of a given message is incorrectly padded
     *               (i.e. a BadPaddingException occurs).
     * @return The decrypted message.
     */
    public static byte[] attack(int blockSize, byte[] ciphertext, Predicate<byte[]> oracle)
    {
        final List<byte[]> message = new ArrayList<>();

        final int padding = getPadding(blockSize, ciphertext, oracle);

        for (int i = 1; i < ciphertext.length/blockSize; i++) {
            byte[] c1 = Arrays.copyOfRange(ciphertext, i * blockSize - blockSize, i * blockSize);
            byte[] c2 = Arrays.copyOfRange(ciphertext, i * blockSize, i * blockSize + blockSize);

            if (i == ciphertext.length/blockSize-1) {
                message.add(Arrays.copyOfRange(decipherBlock(c1, c2, padding, oracle), 0, blockSize - padding));
            } else {
                message.add(decipherBlock(c1, c2, 0, oracle));
            }
        }

        return message.stream()
                .reduce(PaddingAttack::concat)
                .orElseThrow(() -> new IllegalStateException("Failed to combine final message."));
    }

    /**
     * Find the padding used in the last block of a message.
     *
     * @param blockSize The block size
     * @param ciphertext The whole ciphertext (starting with IV)
     * @param oracle Returns true if the decryption of a given message is incorrectly padded
     *               (i.e. a BadPaddingException occurs).
     * @return The padding used in b2.
     */
    private static int getPadding(int blockSize, byte[] ciphertext, Predicate<byte[]> oracle)
    {
        // Second to last block
        byte[] c1 = Arrays.copyOfRange(ciphertext, ciphertext.length - 2*blockSize, ciphertext.length - blockSize);
        // Last block
        byte[] c2 = Arrays.copyOfRange(ciphertext, ciphertext.length - blockSize, ciphertext.length);

        byte[] mask = init(blockSize, (byte) 0x00);

        for (int i = 0; i < blockSize; i++) {

            mask[i] = 0x01;

            if (oracle.test(concat(xor(c1, mask), c2)))
            {
                return blockSize - i;
            }
        }

        throw new IllegalStateException("Failed to resolve padding");
    }

    /**
     * Decipher a block of cipher text and return the (padded) message.
     *
     * @param b1 The previous block / IV
     * @param b2 The block to decipher
     * @param padding A known padding for b2. If b2 is not padded, set to 0.
     * @param oracle Returns true if the decryption of a given message is incorrectly padded
     *               (i.e. a BadPaddingException occurs).
     * @return The plaintext of b2.
     */
    private static byte[] decipherBlock(byte[] b1, byte[] b2, int padding, Predicate<byte[]> oracle) {
        final int blockSize = b1.length;

        // What we know about the message
        // |-> block - p times          | known message bytes |-> p times
        // 0x00 0x00 0x00 0x00 0x00 ... 0xii 0xii ...         0xpp 0xpp 0xpp ...
        byte[] m0 = concat(init(blockSize - padding, (byte) 0x00), init(padding, (byte) (padding)));

        // p is the padding for each round
        for (int p = padding; p < blockSize; p++) {

            // What the decryption algorithm is supposed to see
            // |-> block - p times         |-> p times
            // 0x00 0x00 0x00 0x00 0x00... 0xpp 0xpp 0xpp ...
            byte[] m1 = concat(init(blockSize - p, (byte) 0x00), init(p, (byte) (p + 1)));

            for (int i = 0; i < 0xFF; i++) {
                m1[blockSize - p - 1] = (byte) i;
                byte[] mask = xor(m0, m1);
                if (!oracle.test(concat(xor(b1, mask), b2)))
                {
                    byte ch = (byte) ((p + 1) ^ i);
                    m0[blockSize - p - 1] = ch;
                    break;
                }
            }
        }

        return m0;
    }

    public static byte[] xor(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++)
        {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static byte[] init(int n, byte val)
    {
        byte[] result = new byte[n];
        Arrays.fill(result, val);
        return result;
    }

    public static byte[] concat(byte[] ... a)
    {
        int totalLength = 0;
        for (int i = 0; i < a.length; i++) {
            totalLength += a[i].length;
        }
        byte[] result = new byte[totalLength];

        int n = 0;
        for (byte[] bytes : a) {
            for (int j = 0; j < bytes.length; j++) {
                result[n] = bytes[j];
                n++;
            }
        }
        return result;
    }
}
