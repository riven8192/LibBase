/*
 * Created on 8 jun 2010
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SharingInputStream extends AbstractInputStream {
	private final OutputStream shareWith;

	public SharingInputStream(InputStream in, OutputStream out) {
		super(in);

		this.shareWith = out;
	}

	@Override
	public int read() throws IOException {
		int got = super.read();
		if (got != -1)
			this.shareWith.write(got);
		return got;
	}

	@Override
	public int read(byte[] buf) throws IOException {
		return this.read(buf, 0, buf.length);
	}

	@Override
	public int read(byte[] buf, int off, int len) throws IOException {
		int got = super.read(buf, off, len);
		if (got == -1)
			return -1;
		this.shareWith.write(buf, off, got);
		this.shareWith.flush();
		return got;
	}
}