package craterstudio.streams;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.util.zip.ZipOutputStream;

public class ZipEntryOutputStream extends FilterOutputStream {
	public ZipEntryOutputStream(ZipOutputStream out) {
		super(out);
	}

	@Override
	public void write(int b) throws IOException {
		super.out.write(b);
	}

	@Override
	public void write(byte[] buf) throws IOException {
		super.out.write(buf);
	}

	@Override
	public void write(byte[] buf, int off, int len) throws IOException {
		super.out.write(buf, off, len);
	}

	@Override
	public void close() throws IOException {
		((ZipOutputStream) super.out).closeEntry();
	}
}