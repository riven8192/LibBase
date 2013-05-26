/*
 * Created on 4 jun 2010
 */

package craterstudio.streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;

import craterstudio.text.Text;

public class HttpChunkedOutputStream extends OutputStream {
	private final OutputStream out;
	private final int maxChunkSize;
	private boolean closed;

	public HttpChunkedOutputStream(OutputStream out, int maxChunkSize) {
		this.out = out;
		this.maxChunkSize = maxChunkSize;
		this.closed = false;
	}

	private final byte[] oneByte = new byte[1];

	@Override
	public void write(int b) throws IOException {
		this.oneByte[0] = (byte) b;
		this.write(this.oneByte);
	}

	@Override
	public void write(byte[] buf) throws IOException {
		this.write(buf, 0, buf.length);
	}

	@Override
	public void write(byte[] buf, int off, int len) throws IOException {
		if (this.closed)
			throw new EOFException();

		for (int rem = len; rem > 0;) {
			int send = Math.min(rem, this.maxChunkSize);

			this.out.write(Text.ascii(Integer.toHexString(send) + "\r\n"));
			this.out.write(buf, off, send);
			this.out.write(Text.ascii("\r\n"));
			// this.out.flush();

			off += send;
			rem -= send;
		}
	}

	@Override
	public void flush() throws IOException {
		if (this.closed)
			throw new EOFException();
		this.out.flush();
	}

	@Override
	public void close() throws IOException {
		if (this.closed)
			return;
		this.closed = true;

		this.out.write(Text.ascii("0\r\n\r\n"));
		this.out.flush();
		this.out.close();
	}
}
