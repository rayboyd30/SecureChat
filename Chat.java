import java.io.DataInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;
import java.util.Scanner;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Chat {
    public static void main(String[] args) {
        parseArgs(new ArrayDeque<String>(Arrays.asList(args)));
        Socket c = null;
        if (mode == SERVER) {
            try {
                ServerSocket s = new ServerSocket(port);
                c = s.accept();
		dhKeyExchange(c);
            } catch (IOException e) {
                System.err.println("There was an error opening the server:");
                System.err.println(e);
                System.exit(-3);
            } catch (SecurityException e) {
                System.err.println("You are not allowed to open the server:");
                System.err.println(e);
                System.exit(-2);
            }
        } else if (mode == CLIENT) {
            try {
                c = new Socket(addr, port);
		dhKeyExchange(c);
            } catch (IOException e) {
                System.err.println("There was an error connecting:");
                System.err.println(e);
                System.exit(-3);
            } catch (SecurityException e) {
                System.err.println("You are not allowed to connect:");
                System.err.println(e);
                System.exit(-2);
            }
        } else {
            System.err.println("Please specify the mode.");
            printUsage();
            System.exit(-1);
        }
        try {
            new Thread(new ChatSender(System.in, c.getOutputStream(), encrypt, mode)).start();
            new Thread(new ChatReceiver(c.getInputStream(), System.out, decrypt, mode)).start();
        } catch (IOException e) {
            System.err.println("There was an error setting up data transfer:");
            System.err.println(e);
            System.exit(-3);
        }
    }

    private static void aesProvider() {
	CipherProvider provider = new CipherProvider();
	java.security.Security.insertProviderAt(provider, 1);
	System.out.println(Arrays.toString(Security.getProviders()));
	ivParams = new IvParameterSpec(iv, 0, 16);
	try {
	    encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "CipherProvider");
	    encrypt.init(Cipher.ENCRYPT_MODE, sharedKey, ivParams);
	    decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "CipherProvider");
            decrypt.init(Cipher.DECRYPT_MODE, sharedKey, ivParams);
	} catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchProviderException e) {
	    e.printStackTrace();
	}
    }
    
    private static void dhKeyExchange(Socket s) {
	try {
	    DataInputStream receiver = new DataInputStream(s.getInputStream());
	    DataOutputStream sender = new DataOutputStream(s.getOutputStream());
	    
	    if (mode == SERVER) {
		try {
		    System.out.println("Starting DH key exchange");
		    
		    System.out.println("Creating DH parameters (this may take some time)");
		    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
		    paramGen.init(1024);
		    AlgorithmParameters params = paramGen.generateParameters();
		    byte[] encodedParams = params.getEncoded();
		    
		    System.out.println("Retrieving DH parameter specs");
		    DHParameterSpec paramSpecs = params.getParameterSpec(DHParameterSpec.class);

		    System.out.println("Sending params to client");
		    sender.writeInt(encodedParams.length);
		    sender.write(encodedParams);
		    
		    System.out.println("Generating server's keys");
		    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
		    keyPairGen.initialize(paramSpecs);
		    KeyPair serverKPair = keyPairGen.genKeyPair();
		    PublicKey serverPubKey = serverKPair.getPublic();
		    
		    System.out.println("Reading client's public key");
		    byte[] encodedClientPubK = new byte[receiver.readInt()];
		    receiver.readFully(encodedClientPubK);
		    PublicKey clientPubK = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(encodedClientPubK));

		    System.out.println("Encoding server's public key");
		    byte[] encodedServerPubK = serverPubKey.getEncoded();
		    
		    System.out.println("Sending server's key to client");
		    sender.writeInt(encodedServerPubK.length);
		    sender.write(encodedServerPubK);
		    
		    System.out.println("Initializing key agreement");
		    KeyAgreement agreement = KeyAgreement.getInstance("DH");
		    
		    System.out.println("Initializing agreement with server's private key");
		    agreement.init(serverKPair.getPrivate());
		    agreement.doPhase(clientPubK, true);
		    
		    System.out.println("Initializing shared secret");
		    sharedKey = agreement.generateSecret("AES");
		    System.out.println("DH key exchange was successful");

		    System.out.println("Producing shared IV");
		    agreement.init(serverKPair.getPrivate());
		    agreement.doPhase(clientPubK, true);
		    iv = agreement.generateSecret();
		    aesProvider();
		    
		    System.out.println("Ready to chat");
		    		 		    
		} catch(IllegalStateException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | IOException | 
			InvalidKeyException | InvalidKeySpecException | InvalidParameterSpecException e ){
		    System.out.println(e);
		}
	    } else if (mode == CLIENT) {
		try {
		    System.out.println("Starting DH key exchange");
		    System.out.println("Receiveing params generated by server");
		    byte[] encodedParams = new byte[receiver.readInt()];
		    receiver.readFully(encodedParams);
		    AlgorithmParameters params = AlgorithmParameters.getInstance("DH");
		    params.init(encodedParams);

		    System.out.println("Generating key pair for the client");
		    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
		    keyGen.initialize(params.getParameterSpec(DHParameterSpec.class));
		    KeyPair clientPair = keyGen.genKeyPair();
		    PublicKey clientPubK = clientPair.getPublic();
		    byte[] encodedClientPubK = clientPubK.getEncoded();
		
		    System.out.println("Sending client key to server");
		    sender.writeInt(encodedClientPubK.length);
		    sender.write(encodedClientPubK);
		
		    System.out.println("Receiving server's public key");
		    byte[] encodedServerPubK = new byte[receiver.readInt()];
		    receiver.readFully(encodedServerPubK);
		    PublicKey serverPubK = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(encodedServerPubK));
		    
		    System.out.println("Initializing key agreement");
		    KeyAgreement agreement = KeyAgreement.getInstance("DH");
		    System.out.println("Initializing key agreement with client's private key");
		    agreement.init(clientPair.getPrivate());
		    agreement.doPhase(serverPubK, true);

		    System.out.println("Generating shared secret");
		    sharedKey = agreement.generateSecret("AES");
		    System.out.println("DH key exchange was successful");
		    
		    System.out.println("Producing shared IV");
		    agreement.init(clientPair.getPrivate());
		    agreement.doPhase(serverPubK, true);
		    iv = agreement.generateSecret();
		    aesProvider();
		    System.out.println("Ready to chat");
		    

		} catch (IllegalStateException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | IOException |
                        InvalidKeyException | InvalidKeySpecException | InvalidParameterSpecException e) {
		    System.out.println(e);
		    System.exit(-2);
		}
		
		
	    } else {
		System.err.println("Must specify client or server mode");
		System.exit(-2);
	    }
	} catch(IOException e) {
	    System.out.println(e);
	    System.exit(-2);
	}
    }

    private static void parseArgs(Queue<String> args) {
        while (args.peek() != null) {
            String opt = args.poll();
            if (opt.equals("-s")) {
                if (mode != UNSPECIFIED) {
                    printUsage();
                    System.exit(-1);
                }
                mode = SERVER;
                parsePort(args);
            } else if (opt.equals("-c")) {
                if (mode != UNSPECIFIED) {
                    printUsage();
                    System.exit(-1);
                }
                mode = CLIENT;
                parseAddr(args);
                parsePort(args);
            }
        }
    }
    private static void badPort() {
        System.err.println("Please specify a port between 1 and 65535.");
        printUsage();
        System.exit(-1);
    }
    private static void parsePort(Queue<String> args) {
        String strPort = args.poll();
        if (strPort == null) {
            badPort();
        }
        try {
            port = Integer.parseInt(strPort);
        } catch (NumberFormatException e) {
            badPort();
        }
        if (!(1 <= port && port <= 65535)) {
            badPort();
        }
    }
    private static void badAddr() {
        System.err.println("Please specify an IP address or host name.");
        printUsage();
        System.exit(-1);
    }
    private static void parseAddr(Queue<String> args) {
        String hostname = args.poll();
        if (hostname == null) {
            badAddr();
        }
        try {
            addr = InetAddress.getByName(hostname);
        } catch (UnknownHostException e) {
            System.err.println("The address '" + hostname + "' is unrecognized or could not be resolved.");
            badAddr();
        } catch (SecurityException e) {
            System.err.println("You are not allowed to resolve '" + hostname + "'.");
            System.exit(-2);
        }
    }
    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("    java Chat -s PORT");
        System.err.println("    invokes Chat in server mode attempting to listen on PORT.");
        System.err.println("");
        System.err.println("    java Chat -c ADDRESS PORT");
        System.err.println("    invokes Chat in client mode attempting to connect to ADDRESS on PORT.");
    }

    private static final byte UNSPECIFIED = 0;
    private static final byte SERVER = 1;
    private static final byte CLIENT = 2;

    private static byte mode = UNSPECIFIED;
    private static InetAddress addr = null;
    private static int port = 0;
    
    private static Cipher encrypt;
    private static Cipher decrypt;
    private static byte[] iv;
    private static SecretKey sharedKey;
    private static AlgorithmParameterSpec ivParams;
}

class ChatSender implements Runnable {
    public ChatSender(InputStream screen, OutputStream conn, Cipher encrypter, byte mode) {
        this.screen = new Scanner(screen);
        this.conn = new PrintStream(conn);
	this.chatMode = mode;
	this.encrypt = encrypter;
    }
    public void run() {
	sender = new DataOutputStream(conn);
        while (true) {
            String line = screen.nextLine();
	    try {
	        byte[] msgToSend = encrypt.doFinal(line.getBytes());
		sender.writeInt(msgToSend.length);
		sender.write(msgToSend, 0, msgToSend.length); 
	    } catch (BadPaddingException | IOException | IllegalBlockSizeException e) {
		System.out.println(e);
	    }
        }
    }

    private Scanner screen;
    private PrintStream conn;
    private byte chatMode;
    private Cipher encrypt;
    private DataOutputStream sender;
}

class ChatReceiver implements Runnable {
    public ChatReceiver(InputStream conn, OutputStream screen, Cipher decrypt, byte mode) {
	this.decrypt = decrypt;
	this.chatMode = mode;
        this.conn = conn;
        this.screen = screen;
    }
    public void run() {
        byte[] msg;
	byte[] msgCoded;
	receiver = new DataInputStream(conn);

        while (true) {
            try {
		int len = receiver.readInt();
                if (len == -1) break;

		msgCoded = new byte[len];
		receiver.readFully(msgCoded);
		msg = decrypt.doFinal(msgCoded);
		
		if (chatMode == SERVER) {
		    System.out.printf("Client: ");
		} else if (chatMode == CLIENT) {
		    System.out.printf("Server: ");
		}
		
                screen.write(msg, 0, msg.length);
		System.out.printf("\n");
            } catch (IOException | BadPaddingException | IllegalBlockSizeException e) {
                System.err.println("There was an error receiving data:");
                System.err.println(e);
		System.exit(-2);
            }
        }
    }
    
    private static final byte SERVER = 1;
    private static final byte CLIENT = 2;
    private Cipher decrypt;
    private byte chatMode;
    private DataInputStream receiver;
    private InputStream conn;
    private OutputStream screen;
}
