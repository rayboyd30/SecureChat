
import java.security.Provider;

/**
 * A Provider that links the AES cipher from Project 1 into the JCE
 */
public class CipherProvider extends Provider {
    /**
     * Constructor.
     *
     * Use this with java.security.Security.insertProviderAt() to install this
     * provider into your Chat project.
     */
    public CipherProvider() {
        super("CipherProvider", 1.0, "Provider for AES");

        put("Cipher.AES", "AESCipher");
    }
}
