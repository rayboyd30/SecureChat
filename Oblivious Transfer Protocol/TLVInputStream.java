
import java.io.InputStream;
import java.io.IOException;

import java.nio.ByteBuffer;

public class TLVInputStream {
    public TLVInputStream(InputStream in) {
        this.in = in;
    }
    public byte[] get(byte type) throws TLVException, IOException {
        // read and parse the header
        byte[] header_data = new byte[3];
        in.read(header_data);
        ByteBuffer header = ByteBuffer.wrap(header_data);
        byte recv_type = header.get();
        if (recv_type != type) {
            throw new TLVException("Unexpected type in TLV.");
        }
        short length = header.getShort();

        // read the data
        byte[] data = new byte[length];
        in.read(data);
        return data;
    }
    public byte[] get(int type) throws TLVException, IOException {
        return get((byte)type);
    }
    public byte getByte(byte type) throws TLVException, IOException {
        byte[] data = get(type);
        if (data.length == 1) {
            return data[0];
        } else {
            throw new TLVException("Unexepected length in TLV for Byte.");
        }
    }
    public byte getByte(int type) throws TLVException, IOException {
        return getByte((byte)type);
    }

    private InputStream in;
}
