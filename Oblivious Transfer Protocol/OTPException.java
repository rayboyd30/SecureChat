
import java.security.GeneralSecurityException;

public class OTPException extends GeneralSecurityException {
    public OTPException() {
        super();
    }
    public OTPException(String msg) {
        super(msg);
    }
    public OTPException(String message, Throwable cause) {
        super(message, cause);
    }
    public OTPException(Throwable cause) {
        super(cause);
    }
}
