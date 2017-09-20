
import java.io.OutputStream;
import java.io.IOException;

import java.nio.ByteBuffer;

public class TLVOutputStream {
    public TLVOutputStream(OutputStream out) {
        this.out = out;
    }
    public void put(byte type, byte[] data) throws IOException {
        // construct a header with this format: | type |      size      |
        ByteBuffer header = ByteBuffer.allocate(3);
        header.put(type);
        header.putShort((short)data.length);
        
        // write the header and data
        out.write(header.array());
        out.write(data);
    }
    public void put(int type, byte[] data) throws IOException {
        put((byte)type, data);
    }
    public void putByte(byte type, byte b) throws IOException {
        byte[] data = new byte[1];
        data[0] = b;
        put(type, data);
    }
    public void putByte(int type, byte b) throws IOException {
        putByte((byte)type, b);
    }
    
    private OutputStream out;
}
