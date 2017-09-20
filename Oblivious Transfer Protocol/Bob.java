import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Bob
{
    //constructor instantiates TLV Streams
    public Bob(InputStream in, OutputStream out)
    {
		this.in = new TLVInputStream(in);
		this.out = new TLVOutputStream(out);
    }

    //driver adapted from Alice.java
    public static void main(String[] args) {
	Security.addProvider(new csec2017.CSec2017Prov());
	/*        Security.addProvider(
		  new org.bouncycastle.jce.provider.BouncyCastleProvider());*/
	int result = -10; // Some result code not used anywhere else
	System.err.print("Waiting for connection on port 8023: ");
	try {
	    Socket c = new Socket("localhost", 8023);
	    System.err.println("Connected.");

	    Bob sideB = new Bob(c.getInputStream(), c.getOutputStream());
	    result = sideB.execute();
	} catch (OTPCheatException e) {
	    e.printStackTrace();
	    System.err.println("\nCheating Detected: " + e);
	    System.exit(-1);
	} catch (java.io.IOException e) {
	    e.printStackTrace();
	    System.err.println("\nError opening socket: " + e);
	    System.exit(-2);
	} catch (OTPException e) {
	    e.printStackTrace();
	    System.err.println("\nError executing OTP: " + e);
	    System.exit(-3);
	} catch (TLVException e) {
	    e.printStackTrace();
	    System.err.println("\nCommunication error executing OTP: " + e);
	    System.err.println("This typically occurs when Alice disconnects," +
			       " crashes, or sends a message out of order.");
	    System.exit(-4);
	}

	switch (result) {
	case Outcome.LOSE: {
	    System.out.println("I Lose");
	} break;
	case Outcome.WIN: {
	    System.out.println("I Win");
	} break;
	default: {
	    // This should never happen
	    System.err.println("Internal Error");
		}
	}
	System.exit(result);
    }

   int execute() throws OTPException
    {
		KeyGenerator key_gen = null;
		try {
			key_gen = KeyGenerator.getInstance("AES");
			key_gen.init(256);
		} catch (InvalidParameterException a) {
			throw new OTPException("Invalid parameter exception on Bob's side", a);
		} catch (NoSuchAlgorithmException a) {
			throw new OTPException("Can't get instance of AES", a);
		}

		Charset utf8 = Charset.forName("UTF-8");

		//Step 1, performed by Alice
		System.err.println(1);
		System.out.println("Alice is generating symmetric key");

		//Step 2, Bob generates symmetric key
		System.err.println(2);
		System.out.println("Bob is generating symmetric key");
		SecretKey K_B = key_gen.generateKey();

		//Step 3, Bob gets public keys
		System.err.println(3);
		System.out.println("Bob is getting the public keys from Alice");
		byte[] K_I_data = null;
		byte[] K_J_data = null;
		PublicKey K_I_pub = null;
		PublicKey K_J_pub = null;
		try {
		    K_I_data = in.get(0x30);
			 K_I_pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_I_data));
		    K_J_data = in.get(0x31);
			 K_J_pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_J_data));
		} catch (IOException a) {
			throw new OTPException("Bob unable to receive keys", a);
		} catch (InvalidKeySpecException a) {
			a.printStackTrace();
		} catch (NoSuchAlgorithmException a) {
			a.printStackTrace();
		}

		// check for cheating
		PublicKey K_I_Pub = null;
		try {
		    K_I_Pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_I_data));
		} catch (InvalidKeySpecException a) {
		    System.out.println("Invalid Key spec exception.");
		} catch (NoSuchAlgorithmException a) {
		    System.out.println("No such algorithm exception.");
		}

	        if (K_J_pub.equals(K_I_pub)) {
			throw new OTPCheatException("Cheating detected: Alice sent duplicate public keys.");
		    }

		//Step 4, Bob chooses H
		System.err.println(4);
		System.out.println("Sending symmetric keys to Alice");
		byte H = (byte)(new BigInteger(1, random).intValue());
		Key K_H = null;
	        if (H == 0) {
		    K_H = K_I_pub;
		} else {
		    K_H = K_J_pub;
		}
		byte[] K_B_H = null;
		try {
			try {
				K_B_H = Common.encryptKey((RSAPublicKey)K_H, K_B, random);
			} catch (InvalidKeyException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException a) {
						 a.printStackTrace();
			}
			out.put(0x40, K_B_H);
		} catch (IOException a) {
			throw new OTPException("Bob failed to send KeyBH", a);
		}

		//Step 5, Alice decrypts KeyB
		System.err.println(5);
		System.out.println("Alice is flipping coin");

		//Step 6, Bob gets encrypted message
		System.err.println(6);
		System.out.println("Bob is receiving the encrypted message");

		byte[] msg;
		try {
			msg = in.get(0x60);
		} catch (IOException a) {
			throw new OTPException("Bob failed to retrieve the encrypted message");
		}

		byte G = 0;
		try {
			G = in.getByte(0x61);
		} catch (IOException a)	{
			throw new OTPException("Bob failed to retrieve the coin flip");
		}

		//Step 7, decrypt message. send message and coin flip call
		System.err.println(7);
		System.out.println("Bob is decrypting Alice's message");

		Key K_A = null;
		if(G == 0){
		    K_A = K_I_pub;
		} else {
		    K_A = K_J_pub;
		}

		try {
			Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
			aes.init(Cipher.DECRYPT_MODE, K_B);
			byte[] msgData = aes.doFinal(msg);
			String result = new String(msgData, utf8);
			out.put(0x70, msgData);
		} catch (NoSuchPaddingException a) {
			throw new OTPException("No such padding exception ", a);
		} catch (InvalidKeyException a) {
			throw new OTPException("Invalid Key Exception", a);
		} catch (BadPaddingException a) {
			throw new OTPException("Bad padding exception", a);
		} catch (NoSuchAlgorithmException a) {
			throw new OTPException("No Such Algorithm Exception", a);
		} catch (IllegalBlockSizeException a) {
			throw new OTPException("Illegal block size exception", a);
		} catch (IOException a) {
			throw new OTPException("IOException", a);
		}

		try {
			out.putByte(0x71, H);
		} catch (IOException a) {
			throw new OTPException(a);
		}

		//Step 8, receive private keys, check for commutative, duplicates, etc.
		System.err.println(8);
		System.out.println("Bob is receiving the private keys");
		byte[] K_I_bytesB = null;
		byte[] K_J_bytesB = null;
		try {
			K_I_bytesB = in.get(0x80);
			K_J_bytesB = in.get(0x81);
		} catch (IOException a) {
			throw new OTPException(a);
		}

		if (!(((RSAPublicKey)K_I_pub).getModulus().equals(((RSAPublicKey)K_J_pub).getModulus())))
		{
			throw new OTPCheatException("Alice is cheating, the public keys were not commutative");
		}

		PrivateKey K_I_private = null;
		try {
			K_I_private = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(K_I_bytesB));
		} catch (InvalidKeySpecException a) {
			throw new OTPException(a);
		} catch (NoSuchAlgorithmException a) {
			throw new OTPException(a);
		}

		PrivateKey K_J_private = null;
		try {
			K_J_private = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(K_J_bytesB));
		} catch (InvalidKeySpecException a) {
			throw new OTPException(a);
		} catch (NoSuchAlgorithmException a) {
		    throw new OTPException(a);
		}

		//check for duplicate private keys
		if(K_I_private.equals(K_J_private)){
		    throw new OTPCheatException("Cheating detected: Alice sent duplicate private keys");
		}

		//check for keys being used in reverse
		Key doubleCheck = null;
		try {
		    doubleCheck = Common.decryptKey((RSAPrivateKey)K_I_private, Common.encryptKey((RSAPublicKey)K_I_pub, K_B, random));
		    if(!K_B.equals(doubleCheck)){
			throw new OTPCheatException("Cheating detected: Alice used K_I and K_J in reverse.");
		    }
		} catch (InvalidKeyException a) {
		    System.out.println("Invalid Key Exception.");
		} catch (BadPaddingException a) {
		    System.out.println("Bad Padding Exception.");
		} catch (NoSuchPaddingException a) {
		    System.out.println("No Such Padding Exception.");
		} catch (IllegalBlockSizeException a) {
		    System.out.println("Illegal Block Size Exception.");
		} catch (NoSuchAlgorithmException a) {
		    System.out.println("No Such Algorithm Exception.");
		}

		if(G != H) {
			return Outcome.LOSE;
		} else {
			return Outcome.WIN;
		}
    }

    private TLVInputStream in;
    private TLVOutputStream out;
    private SecureRandom random = new SecureRandom();
    private String msg = "I win. You lose."; //mult of 16
}
