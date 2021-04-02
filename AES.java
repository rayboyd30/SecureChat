
public class AES 
{
    static final byte[] invSBox = 
    {
	(byte)0x52,(byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38, 
	(byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81,(byte)0xf3, (byte)0xd7, (byte)0xfb,
	(byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87, 
	(byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb,
	(byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d, 
	(byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e,
	(byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2, 
	(byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25, 
	(byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, 
	(byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92, 
	(byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, 
	(byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84, 
	(byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a, 
	(byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06, 
	(byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02, 
	(byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b, 
	(byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea, 
	(byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73, 
	(byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85, 
	(byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e, 
	(byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89, 
	(byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b, 
	(byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20, 
	(byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4, 
	(byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31, 
	(byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f, 
	(byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d, 
	(byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef, 
	(byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0, 
	(byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61, 
	(byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26, 
	(byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d
    };
    
    static final byte[] sBox = 
    {
	(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5, 
	(byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76,
	(byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0, 
	(byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0,
	(byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc, 
	(byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15,
	(byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a, 
	(byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75,
	(byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0, 
	(byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84,
	(byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b, 
	(byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf,
	(byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85, 
	(byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8,
	(byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5, 
	(byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2,
	(byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17, 
	(byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73,
	(byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88, 
	(byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb,
	(byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, 
	(byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79,
	(byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9, 
	(byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08,
	(byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, 
	(byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a,
	(byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e, 
	(byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e,
	(byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, 
	(byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf,
	(byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68, 
	(byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16
    };
    
    private byte[] key;
    private byte[][] state;
    private int nR;
    private byte[] expandedKey;

    //constructor that assigns private variables key and nR
    public AES(byte[] key)
    {
	key = key;
	state = new byte[4][4];
	if(key.length == 16)
	    {  
		nR = 10;
	    }
	if(key.length == 24)
	    {
		nR = 12;
	    }
	if(key.length == 32)
	    {
		nR = 14;
	    }
	
	expandedKey = expandKey(key);
	
    }
    
    public byte[] encrypt(byte[] in)
    {
	byte[] out = new byte[16];
	int index = 0;
	for(int i = 0; i < 4; i++)
	    {
		state[0][i] = in[index];
		state[1][i] = in[index+1];
		state[2][i] = in[index+2];
		state[3][i] = in[index+3];
		index += 4;
	    }

    	byte expandedKeyWords[] = {expandedKey[0], expandedKey[1], expandedKey[2], expandedKey[3], 
			      expandedKey[4], expandedKey[5], expandedKey[6], expandedKey[7], 
			      expandedKey[8], expandedKey[9], expandedKey[10], expandedKey[11], 
			      expandedKey[12],expandedKey[13], expandedKey[14], expandedKey[15]};
    	state = addRoundKey(state,expandedKeyWords);

    	for(int i = 1; i <= nR-1; i++){
	        state = subBytes(state);
    		state = shiftRows(state);
    		state = mixColumns(state);
    		expandedKeyWords = new byte[] {expandedKey[4*(i*4)], expandedKey[4*(i*4) + 1], expandedKey[4*(i*4) + 2], expandedKey[4*(i*4) + 3], 
				      expandedKey[4*(i*4) + 4], expandedKey[4*(i*4) + 5], expandedKey[4*(i*4) + 6], expandedKey[4*(i*4) + 7], 
				      expandedKey[4*(i*4) + 8], expandedKey[4*(i*4) + 9], expandedKey[4*(i*4) + 10], expandedKey[4*(i*4) + 11], 
				      expandedKey[4*(i*4) + 12], expandedKey[4*(i*4) + 13], expandedKey[4*(i*4) + 14], expandedKey[4*(i*4) + 15]};
    		state = addRoundKey(state , expandedKeyWords);
    	}
    	
    	state = subBytes(state);
    	state = shiftRows(state);
    	
    	expandedKeyWords = new byte[] {expandedKey[4*(nR*4)], expandedKey[4*(nR*4) + 1], expandedKey[4*(nR*4) + 2], expandedKey[4*(nR*4) + 3], 
				  expandedKey[4*(nR*4) + 4], expandedKey[4*(nR*4) + 5], expandedKey[4*(nR*4) + 6], expandedKey[4*(nR*4) + 7], 
				  expandedKey[4*(nR*4) + 8], expandedKey[4*(nR*4) + 9], expandedKey[4*(nR*4) + 10], expandedKey[4*(nR*4) + 11], 
				  expandedKey[4*(nR*4) + 12], expandedKey[4*(nR*4) + 13], expandedKey[4*(nR*4) + 14], expandedKey[4*(nR*4) + 15]};
        state = addRoundKey(state, expandedKeyWords);
	
	index = 0;
	for(int i = 0; i < 4; i++)
	    {
		out[index] = state[0][i];
		out[index + 1] = state[1][i];
		out[index + 2] = state[2][i];
		out[index + 3] = state[3][i];
		index += 4;
	    }

	return out; 
	
    }
    
    
    public byte[] decrypt(byte[] in)
    { 
	byte[] out = new byte[16];
        int index = 0;
        for(int i = 0; i < 4; i++)
            {
                state[0][i] = in[index];
                state[1][i] = in[index+1];
                state[2][i] = in[index+2];
                state[3][i] = in[index+3];
                index += 4;
            }
	byte expandedKeyWords[] = {expandedKey[4*(nR*4)], expandedKey[4*(nR*4) + 1], expandedKey[4*(nR*4) + 2], expandedKey[4*(nR*4) + 3], 
				  expandedKey[4*(nR*4) + 4], expandedKey[4*(nR*4) + 5], expandedKey[4*(nR*4) + 6], expandedKey[4*(nR*4) + 7], 
				  expandedKey[4*(nR*4) + 8], expandedKey[4*(nR*4) + 9], expandedKey[4*(nR*4) + 10], expandedKey[4*(nR*4) + 11], 
				  expandedKey[4*(nR*4) + 12], expandedKey[4*(nR*4) + 13], expandedKey[4*(nR*4) + 14], expandedKey[4*(nR*4) + 15]};

	state = addRoundKey(state, expandedKeyWords);
	for(int i = nR-1; i >= 1; i--)
	    {   
		state = invShiftRows(state);
		state = invSubBytes(state);  
		expandedKeyWords = new byte[] {expandedKey[4*(i*4)], expandedKey[4*(i*4) + 1], expandedKey[4*(i*4) + 2], expandedKey[4*(i*4) + 3], 
					      expandedKey[4*(i*4) + 4], expandedKey[4*(i*4) + 5], expandedKey[4*(i*4) + 6], expandedKey[4*(i*4) + 7], 
					      expandedKey[4*(i*4) + 8], expandedKey[4*(i*4) + 9], expandedKey[4*(i*4) + 10], expandedKey[4*(i*4) + 11], 
					      expandedKey[4*(i*4) + 12], expandedKey[4*(i*4) + 13], expandedKey[4*(i*4) + 14], expandedKey[4*(i*4) + 15]};

		state = addRoundKey(state, expandedKeyWords);
		state = invMixColumns(state);
	    }
	state = invShiftRows(state);
	state = invSubBytes(state);
	expandedKeyWords = new byte[] {expandedKey[0], expandedKey[1], expandedKey[2], expandedKey[3], 
				      expandedKey[4], expandedKey[5], expandedKey[6], expandedKey[7], 
				      expandedKey[8], expandedKey[9], expandedKey[10], expandedKey[11], 
				      expandedKey[12],expandedKey[13], expandedKey[14], expandedKey[15]};

	state = addRoundKey(state, expandedKeyWords);
	index = 0;
        for(int i = 0; i < 4; i++)
            {
                out[index] = state[0][i];
                out[index + 1] = state[1][i];
                out[index + 2] = state[2][i];
                out[index + 3] = state[3][i];
                index += 4;
            }
	return out;
    }
 
    // Method to add four byte words through a bitwise XOR
    private byte[] addWords(byte[] word1, byte[] word2)
    {
	byte[] result = new byte[4];
	for (int i = 0; i < 4; i++)
	    {
		result[i] = (byte)((word1[i] ^ word2[i]) & (byte)0xff);
	    }

	return result;
    }
    
    //Method to multiply four byte words according to the equation 4.12
    private byte[] multWords(byte[] word1, byte[] word2)
    {
	byte[] result = new byte[4];
	result[0] = (byte)(multBytes(word1[0], word2[0]) ^ multBytes(word1[3], word2[1]) ^ multBytes(word1[2], word2[2]) ^ multBytes(word1[1], word2[3]));
	result[1] = (byte)(multBytes(word1[1], word2[0]) ^ multBytes(word1[0], word2[1]) ^ multBytes(word1[3], word2[2]) ^ multBytes(word1[2], word2[3]));
	result[2] = (byte)(multBytes(word1[2], word2[0]) ^ multBytes(word1[1], word2[1]) ^ multBytes(word1[0], word2[2]) ^ multBytes(word1[3], word2[3]));
	result[3] = (byte)(multBytes(word1[3], word2[0]) ^ multBytes(word1[2], word2[1]) ^ multBytes(word1[1], word2[2]) ^ multBytes(word1[0], word2[3]));

	return result;
    }

    //Method to multiply bytes according to section 4.2
    private byte multBytes(byte a, byte b) {
	
	byte product = 0;
	   
	for (int n = 0; n < 8; n++) 
	    {
	       
		product = (byte)(((b & 0x01) > 0) ? product^a : product);
	          
		boolean highBitSet = ((a & 0x80) > 0);
	          
		a = (byte)((a<<1) & 0xFE);
	          
		if (highBitSet)
		    a = (byte)(a ^ 0x1b);
                 
		b = (byte)((b>>1) & (byte)0x7F);
	    }

	return product;
    }
    
    //Method to substitute bytes according to the sbox
    private byte[][] subBytes(byte[][] in) {
    	byte[][] result = new byte[4][4];
    	for (int i = 0 ; i < 4 ; i++) 
    	    {
    		for(int j = 0; j < 4; j++)
    		    {
    			int a = in[i][j];
    			int row = (a >> 4) & 0x000F;
    			int col = a & 0x000F;   
    			result[i][j] = sBox[row * 16 + col];
    		    }
    	}

    	return result;
        }
    
    
    //Method to implement Shift Row procedure
    private byte[][] shiftRows(byte[][] in)
    {
	byte[][] out = new byte[4][4];
	
      
	for(int i = 0; i < 4; i++)
	    {
		for(int j = 0; j < 4; j++)
		    {
			if (i == 1)
			    {
				out[i][(j + 3) % 4] = in[i][j];
			    }
			else if (i == 2)
			    {
				out[i][(j + 2) % 4] = in[i][j];
			    }
			else if (i == 3)
			    {
				out[i][(j + 1) % 4] = in[i][j];
			    }
			else
			    {
				out[i][j] = in[i][j];
			    }
		    }
	    }

	return out;
    }
    
    //Method to implement mixColumns procedure
    private byte[][] mixColumns(byte[][] in)
    {
	  byte[][] out = new byte[4][4];
	  for (int col = 0; col < 4; col++)
	      {
		  out[0][col] = (byte)(multBytes((byte)0x02, in[0][col]) ^ multBytes((byte)0x03, in[1][col]) ^ in[2][col] ^ in[3][col]); 
		  out[1][col] = (byte)(in[0][col] ^ multBytes((byte)0x02, in[1][col]) ^ multBytes((byte)0x03, in[2][col]) ^ in[3][col]);
		  out[2][col] = (byte)(in[0][col] ^ in[1][col] ^ multBytes((byte)0x02, in[2][col]) ^ multBytes((byte)0x03, in[3][col]));
		  out[3][col] = (byte)(multBytes((byte)0x03, in[0][col]) ^ in[1][col] ^ in[2][col] ^ multBytes((byte)0x02, in[3][col]));
	      }
	
	  return out;
    }
    
    
    //Method to substitute bytes in the state according to the inverse S-box
    private byte[][] invSubBytes(byte[][] in) {
	byte[][] result = new byte[4][4];
	for (int i = 0 ; i < 4 ; i++) 
	    {
		for(int j = 0; j < 4; j++)
		    {
			int a = in[i][j];
			int row = (a >> 4) & 0x000F;
			int col = a & 0x000F;   
			result[i][j] = invSBox[row * 16 + col];
		    }
	}

	return result;
    }
  
    //Method which implements the inverse shift rows operation
    private byte[][] invShiftRows(byte[][] in)
    {
	byte[][] out = new byte[4][4];
	
      
	for(int i = 0; i < 4; i++)
	    {
		for(int j = 0; j < 4; j++)
		    {
			if (i == 1)
			    {
				out[i][(j + 1) % 4] = in[i][j];
			    }
			else if (i == 2)
			    {
				out[i][(j + 2) % 4] = in[i][j];
			    }
			else if (i == 3)
			    {
				out[i][(j + 3) % 4] = in[i][j];
			    }
			else
			    {
				out[i][j] = in[i][j];
			    }
		    }
	    }

	return out;
    }
    
    //Method which implements the inverse mix column operation
    private byte[][] invMixColumns(byte[][] in)
      {
	  byte[][] out = new byte[4][4];
	  for (int col = 0; col < 4; col++)
	      {
		  out[0][col] = (byte)(multBytes((byte)0x0E, in[0][col]) ^ multBytes((byte)0x0B, in[1][col]) ^ multBytes((byte)0x0D, in[2][col]) ^ multBytes((byte)0x09, in[3][col])); 
		  out[1][col] = (byte)(multBytes((byte)0x09, in[0][col]) ^ multBytes((byte)0x0E, in[1][col]) ^ multBytes((byte)0x0B, in[2][col]) ^ multBytes((byte)0x0D, in[3][col]));
		  out[2][col] = (byte)(multBytes((byte)0x0D, in[0][col]) ^ multBytes((byte)0x09, in[1][col]) ^ multBytes((byte)0x0E, in[2][col]) ^ multBytes((byte)0x0B, in[3][col]));
		  out[3][col] = (byte)(multBytes((byte)0x0B, in[0][col]) ^ multBytes((byte)0x0D, in[1][col]) ^ multBytes((byte)0x09, in[2][col]) ^ multBytes((byte)0x0E, in[3][col]));
	      }
	
	  return out;
      }

    //Method that creates the key schedule. Returns an array that contains 4 * (nR + 1) words of key data
    private byte[] expandKey(byte[] key)
    {
	byte[] temp = new byte[4];
	byte[] expandedKey = new byte[4 *(4*(nR + 1))];
	int nK = key.length/4;
	int index = 0;

	for(int i = 0; i < nK; i++)
	    {
		expandedKey[index] = key[4*i];
		expandedKey[index+1] = key[(4*i)+1];
		expandedKey[index+2] = key[(4*i)+2];
		expandedKey[index+3] = key[(4*i)+3];
		index += 4;
	    }
	index = nK;

	for(int i = nK; i < 4 * (nR+1); i++)
	    {
		temp[0] = expandedKey[(4*i)-4];
		temp[1] = expandedKey[(4*i)-3];
	        temp[2] = expandedKey[(4*i)-2];
		temp[3] = expandedKey[(4*i)-1];
		
		if(i % nK == 0)
		    {
			temp = addWords(subWord(rotWord(temp)), rCon(i/nK));
		    }
		else if((nK > 6 ) && (i % nK == 4))
			    {
				temp = subWord(temp);
			    }

		expandedKey[4*i] = (byte)(expandedKey[index - nK] ^ temp[0]);
		expandedKey[(4*i)+1] = (byte)(expandedKey[index - nK + 1] ^ temp[1]);
		expandedKey[(4*i)+2] = (byte)(expandedKey[index - nK + 2] ^ temp[2]);
		expandedKey[(4*i)+3] = (byte)(expandedKey[index - nK + 3] ^ temp[3]);
		index += 4;
	    }
	return expandedKey;
    }
    
    //Method that returns the value of the round constant for the index passed as a parameter
    private byte[] rCon(int index)
    {
	byte temp  = 0x02;
	byte[] out = new byte[4];
	if (index == 1)
	    {
		out[0] = 0x01;
		out[1] = 0x00;
		out[2] = 0x00;
		out[3] = 0x00;
	    } 
	else
	    {
		for(int i = 1; i < index-1; i++)
		    {
			temp = (byte)multBytes(temp, (byte)0x02); 
		    }
		out[0] = temp;
		out[1] = 0x00;
		out[2] = 0x00;
		out[3] = 0x00;
	    }
	return out;
    }
    
    //Method that substitutes each byte of the word passed as a parameter according to the sBox 
    private byte[] subWord(byte[] in)
    {
	for(int i = 0; i < 4; i++)
	    {
		int a = in[i];
		int row = (a >> 4) & 0x000F;
		int col = a & 0x000F;
		in [i] = sBox[row * 16 + col];
	    }

	return in;
    }
    
    //Method that rotates a word. [a0, a1, a2, a3] passed as a parameter returns [a1, a2, a3, a0]
    private byte[] rotWord(byte[] in)
    {
	byte[] temp = new byte[4];
	temp[0] = in[1];
	temp[1] = in[2];
	temp[2] = in[3];
	temp[3] = in[0];

	return temp;
    }
    
    //Method that performs a bitwise XOR of each column of the state and roundKey 
    private byte[][] addRoundKey(byte[][] in, byte[] roundKey)
    {
	byte[][] out = new byte[4][4];
	int roundKeyIdx = 0;
	for(int i = 0; i < 4; i++)
	    {
		out[0][i] = (byte)(in[0][i] ^ roundKey[roundKeyIdx]);  
		out[1][i] = (byte)(in[1][i] ^ roundKey[roundKeyIdx + 1]);
		out[2][i] = (byte)(in[2][i] ^ roundKey[roundKeyIdx + 2]);
		out[3][i] = (byte)(in[3][i] ^ roundKey[roundKeyIdx + 3]);
		roundKeyIdx += 4;
	    } 
	return out;
    }
}
