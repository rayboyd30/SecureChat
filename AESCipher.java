
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Cipher;

public class AESCipher extends CipherSpi {
    Cipher aesCipher;
    AES cipher;
    byte[] iv = new byte[16];
    byte[] encrypted;
    byte[] temp;
    byte[] buffer;
    boolean do_pad;
    boolean do_cbc;
    int opMode;
    int bufferLen = 0;	

    protected void engineSetMode(String mode)
      throws NoSuchAlgorithmException {
        if (mode.equals("CBC")) {
            do_cbc = true;
        } else if (mode.equals("ECB")) {
            do_cbc = false;
        } else {
            throw new NoSuchAlgorithmException();
        }
    }
    protected void engineSetPadding(String padding)
      throws NoSuchPaddingException {
        if (padding.equals("NoPadding")) {
            do_pad = false;
        } else if (padding.equals("PKCS5Padding")) {
            do_pad = true;
        } else {
            throw new NoSuchPaddingException();
        }
    }
    protected int engineGetBlockSize() {
        return 16; // This is constant for AES.
    }
    protected int engineGetOutputSize(int inputLen) {
  	int outputSize = 0;
	int totalLength = bufferLen + inputLen;
	int bytesInLastBlock = totalLength%16;
	
	if (opMode != Cipher.DECRYPT_MODE && do_pad) {
	    outputSize = totalLength + (16 - bytesInLastBlock);
	} else {
	   outputSize = totalLength - bytesInLastBlock;
	}
	return outputSize;
	
    }
    protected byte[] engineGetIV() {
        byte[] retiv = new byte[16];
        System.arraycopy(iv, 0, retiv, 0, 16);
        return retiv;
    }
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters ap = null;
        try {
            ap = AlgorithmParameters.getInstance("AES");
            ap.init(new IvParameterSpec(engineGetIV()));
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Internal Error: " + e);
        } catch (InvalidParameterSpecException e) {
            System.err.println("Internal Error: " + e);
        }
        return ap;
    }
    protected void engineInit(int opmode, Key key, SecureRandom random)
      throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Internal Error: " + e);
        }
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException {
        try {
            engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
        } catch (InvalidParameterSpecException e) {
            System.err.println("Internal Error: " + e);
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Internal Error: " + e);
        }
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
        buffer = new byte[iv.length];
	bufferLen = 0;

	if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.ENCRYPT_MODE) {
	    opMode = opmode;
	    
	    if (key.getEncoded().length == 16 || key.getEncoded().length == 24 || key.getEncoded().length == 32) {
		
		cipher = new AES(key.getEncoded());
		
		if (do_cbc) {
		    if (params == null) {
			if (opMode == Cipher.ENCRYPT_MODE) {
			    byte[] tempIV = new byte[iv.length];
			    random.nextBytes(tempIV);
			    encrypted = Arrays.copyOf(tempIV, tempIV.length);
			    temp = Arrays.copyOf(tempIV, tempIV.length);
			} else {//decrypt
			    throw new InvalidKeyException("Must provide IV for decryption mode");
			}
		    } else {
			if (params instanceof AlgorithmParameterSpec) {
			    if (params instanceof IvParameterSpec) {
				if(((IvParameterSpec)params).getIV().length == 16) {
				    encrypted = Arrays.copyOf(((IvParameterSpec)params).getIV(), ((IvParameterSpec)params).getIV().length);
				    temp = Arrays.copyOf(((IvParameterSpec)params).getIV(),((IvParameterSpec)params).getIV().length);
				    iv = Arrays.copyOf(((IvParameterSpec)params).getIV(),((IvParameterSpec)params).getIV().length);
				} else {
				    throw new InvalidAlgorithmParameterException("Incorrect IV length. IV length must be 16 bytes.");
				}
			    } else {
				throw new InvalidAlgorithmParameterException("IV is not present");
			    }
			} else {
			    throw new InvalidAlgorithmParameterException("The specs of the IV are incorrect");
			}
		    }
		} else {//ECB
		    if (params == null) {
			encrypted = new byte[16];
			temp = new byte[16];
		    } else {
			throw new InvalidAlgorithmParameterException("ECB does not allow an IV");
		    }
		}
	    } else {
		throw new InvalidKeyException("Key lenth must be 16,24, or 32 bytes");
	    }
	} else {
	    opMode = -1;
	    throw new InvalidAlgorithmParameterException("Must choose encrypt or decrypt mode");
	}
    }
    private int allocateSize(int inputLen) {
        int outputSize = 0;
        int totalLength = bufferLen + inputLen;
        int bytesInLastBlock = totalLength%16;

        if (opMode != Cipher.DECRYPT_MODE && do_pad) {
            outputSize = totalLength + (16 - bytesInLastBlock);
        } else {
	    outputSize = totalLength - bytesInLastBlock;
        }
        return outputSize;
    }
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = new byte[allocateSize(inputLen)];
        int size = 0;
        try {
            size = engineUpdate(input, inputOffset, inputLen, output, 0);
        } catch (ShortBufferException e) {
            System.err.println("Internal Error: " + e);
        }
        return Arrays.copyOf(output, size);
    }
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
        int totalLength = bufferLen + inputLen;
	int blocks = totalLength/16;
	int length = blocks * 16;
	int bytesInLastBlock = totalLength%16;
	int leftOut = inputLen - bytesInLastBlock;
	int offsetCount = 0;
	int outputCalc = outputOffset;

	int buffMeasure = output.length - outputOffset;
	if (buffMeasure < length) {
	    throw new ShortBufferException("Not enough space in the ouptu buffer");
	}

	if (blocks == 0) {
	    for (int i = 0; i < inputLen; i++)
		{
		    buffer[bufferLen + i] = input[inputOffset + i];
		}
	    bufferLen += inputLen;
	    return 0;
	}

	for (int j = 0; j < blocks; j++)
	    {
		for (int i = bufferLen; i < 16; i++)
		    {
			buffer[i] = input[inputOffset + i + offsetCount - bufferLen];
		    }
		offsetCount += 16 - bufferLen;
		bufferLen = 0;

		if (opMode == Cipher.ENCRYPT_MODE) {
		    if (do_cbc) {
			for(int k = 0; k < 16; k++)
			    {
				buffer[k] = (byte) (encrypted[k] ^ buffer[k]);
			    }
		    }
		    
		    buffer = cipher.encrypt(buffer);
		    encrypted = Arrays.copyOf(buffer, 16);
		} else if (opMode == Cipher.DECRYPT_MODE) {
		    if (do_cbc) {
			temp = Arrays.copyOf(buffer, 16);
			buffer = cipher.decrypt(buffer);
			for (int k = 0; k < 16; k++)
			    {
				buffer[k] = (byte) (encrypted[k] ^ buffer[k]);
			    }

			encrypted = Arrays.copyOf(temp, 16);
		    }
		} else {
		    buffer = cipher.decrypt(buffer);
		}

		System.arraycopy(buffer, 0, output, outputOffset + (16 * j), 16);
		outputCalc += 16;
	    }
	
	for (int i = 0; i < bytesInLastBlock; i++) 
	    {
		buffer[bufferLen + i] = input[leftOut + i];
	    }

	bufferLen += bytesInLastBlock;

	return length;
    }
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
        try {
            byte[] temp = new byte[engineGetOutputSize(inputLen)];
            int len = engineDoFinal(input, inputOffset, inputLen, temp, 0);
            return Arrays.copyOf(temp, len);
        } catch (ShortBufferException e) {
            System.err.println("Internal Error: " + e);
            return null;
        }
    }
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int outLen = 0;
	int multOf16 = (inputLen + bufferLen) % 16;

	if (!do_pad && multOf16 != 0) {
	    throw new IllegalBlockSizeException("Total length must be a multiple of 16 when no padding is specified");
	}

	if (do_pad && multOf16 != 0 && opMode == Cipher.DECRYPT_MODE) {
	    throw new IllegalBlockSizeException("The total length must be a multiple of 16 for decryption");
	}

	if (input != null) {
	    outLen = engineUpdate(input, inputOffset, inputLen, output, outputOffset);
	}
	if (do_pad) {
	    if (opMode == Cipher.ENCRYPT_MODE) {
		int paddingLen = 16 - bufferLen;
		byte paddingVal = (byte) paddingLen;
		
		for (int i = bufferLen; i < 16; i++)
		    {
			buffer[i] = paddingVal;
		    }
		if (do_cbc){
		    for (int j = 0; j < 16; j++)
			{
			    buffer[j] = (byte) (encrypted[j] ^ buffer[j]);
			}
		}
		buffer = cipher.encrypt(buffer);
		int lastBlock = output.length - 16;

		for (int h = 0; h < 16; h++)
		    {
			output[lastBlock + h] = buffer[h];
		    }
		outLen += 16;
	    } else {
		//Decrypt mode
		int padIndex = 0;

		if (output.length - 1 != 0) {
		    padIndex = output.length - 1;
		}

		byte padValue = output[padIndex];
		int numPadBytes = padValue;

		if (numPadBytes <= 0 || numPadBytes > 16) {
		    throw new BadPaddingException("There must be between 0 and 16 padding bytes");
		}
		for (int i = 0; i < numPadBytes; i++)
		    {
			if (output[padIndex - i] != padValue) {
			    throw new BadPaddingException("The value of each padding byte must be equal to the total number of padding bytes");
			}
		    }
		outLen -= padValue;
	    }
	} else {
	    buffer = cipher.decrypt(buffer);
	}
	bufferLen = 0;
	buffer = new byte[16];

	if (!do_cbc) {
	    encrypted = new byte[16];
	    temp = new byte[16];
	} else {
	    encrypted = Arrays.copyOf(engineGetIV(), 16);
	    temp = Arrays.copyOf(engineGetIV(), 16);
	}
	
	return outLen;
    }
}

