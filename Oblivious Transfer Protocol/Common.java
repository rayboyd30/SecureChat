
import java.nio.ByteBuffer;

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.spec.SecretKeySpec;

public class Common {
    /**
     * Print the public exponent and modulus of an RSA public key.
     *
     * Useful for debugging
     */
    public static void printRSAPublicKey(RSAPublicKey key) {
        System.err.println(key.getPublicExponent());
        System.err.println(key.getModulus());
    }
    /**
     * Convenience function for printing byte arrays.
     *
     * Useful for debugging.
     */
    public static void printData(byte[] data) {
        for (byte b: data) {
            System.err.printf("%02x ", b);
            System.err.println();
        }
    }
    /**
     * "Wrap" an AES key using an RSA public key.
     *
     * The JCE provider builds several checks into its wrapping and unwrapping
     * methods. These checks often fail if Alice uses the wrong private key.
     *
     * Here, we save the original length of the key and pad it to fill the
     * maximum plaintext block size (discovered by examining the modulus). The
     * padded block is encrypted. Both the key length and the encrypted key are
     * then packed into a byte array.
     */
    public static byte[] encryptKey(RSAPublicKey K_u, SecretKey K,
                                    SecureRandom r)
      throws NoSuchAlgorithmException, InvalidKeyException,
             IllegalBlockSizeException, BadPaddingException,
             NoSuchPaddingException {

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, K_u);
        byte[] K_data = K.getEncoded();
        int block_len = (K_u.getModulus().bitLength() + 7) / 8;
        byte[] plain_key = new byte[block_len];
	r.nextBytes(plain_key);
	plain_key[0] = 0;
        for (int i = 0; i < K_data.length; i++) {
            plain_key[block_len - K_data.length + i] = K_data[i];
        }
        ByteBuffer data = ByteBuffer.allocate(2 + block_len);
        data.putShort((short)K_data.length);
        data.put(c.doFinal(plain_key));
        return data.array();
    }
    /**
     * "Unwrap" an AES key using an RSA private key.
     *
     * (See encryptKey() above).
     *
     * Here, the original key length is read from the array and saved. The rest
     * of the data is decrypted to reveal the padded plaintext. Only the
     * rightmost bytes are extracted to form the unwrapped key.
     */
    public static SecretKey decryptKey(RSAPrivateKey K_r, byte[] data_array)
      throws NoSuchAlgorithmException, InvalidKeyException,
             IllegalBlockSizeException, BadPaddingException,
             NoSuchPaddingException {

        ByteBuffer data = ByteBuffer.wrap(data_array);
        int K_data_len = data.getShort();
        byte[] crypt_key = new byte[data_array.length - 2];
        for (int i = 0; i < crypt_key.length; i++) {
            crypt_key[i] = data_array[i + 2];
        }
        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, K_r);
        byte[] plain_key = c.doFinal(crypt_key);
        byte[] K_data = new byte[K_data_len];
        for (int i = 0; i < K_data_len; i++) {
            K_data[i] = plain_key[plain_key.length - K_data.length + i];
        }
        return new SecretKeySpec(K_data, "AES");
    }
}
