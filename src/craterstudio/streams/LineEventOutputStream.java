/*
 * Created on 27 feb 2008
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;

import craterstudio.data.ByteList;

public class LineEventOutputStream extends OutputStream {
	private final OutputStream out;

	private final byte[] insertBefore;
	private final byte[] insertAfter;

	public LineEventOutputStream(OutputStream out) {
		this(out, null, null);
	}

	public LineEventOutputStream(OutputStream out, byte[] before, byte[] after) {
		this.out = out;
		this.matchLength = 0;
		this.insertBefore = before;
		this.insertAfter = after;
	}

	protected void beforeLine(OutputStream out) throws IOException {
		if (this.insertBefore != null)
			out.write(this.insertBefore);
	}

	protected void afterLine(OutputStream out) throws IOException {
		if (this.insertAfter != null)
			out.write(this.insertAfter);
	}

	private int matchLength;
	private final ByteList currentLine = new ByteList();

	@Override
	public void write(int b) throws IOException {
		this.currentLine.add((byte) b);

		switch (this.matchLength) {
		case 0:
			if (b != '\r') {
				this.matchLength = 0;
				break;
			}
			this.matchLength++;
			break;

		case 1:
			if (b != '\n') {
				this.matchLength = 0;
				break;
			}

			byte[] line = this.currentLine.toArray();
			this.currentLine.clear();

			this.beforeLine(this.out);
			this.out.write(line);
			this.afterLine(this.out);

			this.matchLength = 0;
			break;
		}
	}

	@Override
	public void write(byte[] buf) throws IOException {
		this.write(buf, 0, buf.length);
	}

	@Override
	public void write(byte[] buf, int off, int len) throws IOException {
		for (int i = 0; i < len; i++)
			this.write(buf[off + i]);
	}

	@Override
	public void flush() throws IOException {
		this.out.flush();
	}

	@Override
	public void close() throws IOException {
		if (this.currentLine.size() > 0) {
			byte[] tail = this.currentLine.toArray();
			this.currentLine.clear();

			this.beforeLine(this.out);
			this.out.write(tail);
			this.afterLine(this.out);
		}

		this.out.close();
	}
}
