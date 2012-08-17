/*
 * Created on 16-mei-2005
 */
package craterstudio.io;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipFile;

import craterstudio.text.Text;
import craterstudio.util.HighLevel;

public class Streams {
	public static final int PROCESS_STDOUT = 0;
	public static final int PROCESS_STDERR = 1;

	public static int DEFAULT_BUFFER_SIZE = 8 * 1024;

	public final static void readFully(InputStream in, byte buf[]) throws IOException {
		readFully(in, buf, 0, buf.length);
	}

	public final static void readFully(InputStream in, byte buf[], int off, int len) throws IOException {
		if (len < 0)
			throw new IndexOutOfBoundsException();

		int n = 0;
		while (n < len) {
			int count = in.read(buf, off + n, len - n);
			if (count < 0)
				throw new EOFException();
			n += count;
		}
	}

	/**
	 * WRITE
	 */

	public static final void transferFromBuffer(ByteBuffer buffer, OutputStream output) {
		transferFromBuffer(buffer, output, DEFAULT_BUFFER_SIZE);
	}

	public static final void transferFromBuffer(ByteBuffer buffer, OutputStream output, int block) {
		try {
			buffer.rewind();

			byte[] buf = new byte[block];

			while (buffer.remaining() >= buf.length) {
				buffer.get(buf, 0, buf.length);
				output.write(buf, 0, buf.length);
			}

			int rem = buffer.remaining();
			buffer.get(buf, 0, rem);
			output.write(buf, 0, rem);
		} catch (IOException exc) {
			exc.printStackTrace();
		}
	}

	/**
	 * READ TO BUFFER
	 */

	public static final void transferToBuffer(InputStream input, ByteBuffer buffer) {
		transferToBuffer(input, buffer, DEFAULT_BUFFER_SIZE);
	}

	public static final void transferToBuffer(InputStream input, ByteBuffer buffer, int block) {
		try {
			buffer.rewind();

			byte[] buf = new byte[block];

			while (buffer.hasRemaining()) {
				int max = Math.min(block, buffer.remaining());

				int filled = input.read(buf, 0, max);

				if (filled == -1)
					break;

				buffer.put(buf, 0, filled);
			}
		} catch (Exception exc) {
			exc.printStackTrace();
		}
	}

	/**
	 * COPY
	 */

	public static final long copy(InputStream input, OutputStream output) throws IOException {
		return copy(input, output, false);
	}

	public static final long copy(InputStream input, OutputStream output, boolean consumeReadException) throws IOException {
		byte[] buffer = new byte[4096];

		long copied = 0;

		while (true) {
			int got;
			try {
				got = input.read(buffer);
			} catch (IOException exc) {
				if (!consumeReadException) {
					throw exc;
				}
				got = -1;
			}
			if (got == -1) {
				break;
			}

			output.write(buffer, 0, got);
			copied += got;
		}

		// never consume these IOExceptions, they indicate corrupt state
		try {
			input.close();
		} finally {
			output.close();
		}

		return copied;
	}

	/**
	 * PUMP
	 */

	public static final long pump(InputStream input, OutputStream output) {
		return pump(input, output, true, true);
	}

	public static final long pump(InputStream input, OutputStream output, boolean closeInput, boolean closeOutput) {
		return pump(input, output, closeInput, closeOutput, 8 * 1024);
	}

	public static final long pump(InputStream input, OutputStream output, boolean closeInput, boolean closeOutput, int bufferSize) {
		byte[] buffer = new byte[bufferSize];

		int filled = 0;
		long pumped = 0L;

		try {
			while ((filled = input.read(buffer)) != -1) {
				output.write(buffer, 0, filled);
				output.flush();
				pumped += filled;
			}
		} catch (EOFException exc) {
			// ignore
		} catch (SocketException exc) {
			// ignore
		} catch (SocketTimeoutException exc) {
			// ignore
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		} finally {
			if (closeInput)
				Streams.safeClose(input);

			if (closeOutput)
				Streams.safeClose(output);
		}

		return pumped;
	}

	/**
	 * TRANSFER
	 */

	public static final boolean transfer(InputStream input, OutputStream output) {
		return Streams.transfer(input, output, true, true, null, DEFAULT_BUFFER_SIZE, -1);
	}

	public static final boolean transfer(InputStream input, OutputStream output, boolean closeInput, boolean closeOutput) {
		return Streams.transfer(input, output, closeInput, closeOutput, null, DEFAULT_BUFFER_SIZE, -1);
	}

	public static final boolean transfer(InputStream input, OutputStream output, boolean closeInput, boolean closeOutput, TransferListener transferListener, int bufferSize, int expected) {
		if (bufferSize <= 0)
			throw new IllegalArgumentException();

		boolean hasListener = transferListener != null;
		if (hasListener)
			transferListener.transferInitiated(expected);

		byte[] buffer = new byte[bufferSize];

		int got = 0;

		IOException caught = null;

		try {
			// write what's read
			while ((got = input.read(buffer)) != -1) {
				if (hasListener)
					transferListener.transfered(got);
				output.write(buffer, 0, got);
				output.flush(); // for flushing buffered streams
			}
			output.flush();
		} catch (IOException exc) {
			caught = exc;
		} finally {
			// close streams

			if (closeInput)
				Streams.safeClose(input);

			if (closeOutput)
				Streams.safeClose(output);
		}

		// call appropriate final method
		if (hasListener) {
			transferListener.transferFinished(caught);
			return (caught == null);
		}

		// if (caught != null)
		// throw new IllegalStateException("Could not transfer data between
		// streams", caught);

		return (caught == null);
	}

	public static final void asynchronousTransfer(InputStream input, OutputStream output) {
		asynchronousTransfer(input, output, true, true);
	}

	public static final void asynchronousTransfer(InputStream input, OutputStream output, boolean closeInput, boolean closeOutput) {
		asynchronousTransfer(input, output, closeInput, closeOutput, null, 8 * 1024, -1);
	}

	public static final void asynchronousTransfer(InputStream input, OutputStream output, boolean closeInput, boolean closeOutput, TransferListener transferListener, int bufferSize, int expected) {
		new Thread(new NonBlockingTransfer(input, output, closeInput, closeOutput, transferListener, bufferSize, expected)).start();
	}

	public static final void asynchronousTransfer(InputStream input, OutputStream output, boolean closeInput, boolean closeOutput, TransferListener transferListener, int bufferSize, int expected, int stackSize) {
		new Thread(null, new NonBlockingTransfer(input, output, closeInput, closeOutput, transferListener, bufferSize, expected), null, stackSize).start();
	}

	/**
	 * READ STREAM
	 */

	public static final void readStreamTo(InputStream input, byte[] dst, int chunk) {
		try {
			int off = 0;
			while (true)

			{
				int len = Math.min(dst.length - off, chunk);
				if (len == 0)
					break;
				int bytes = input.read(dst, off, len);
				if (bytes == -1)
					throw new IllegalStateException("unexpected EOF");
				off += bytes;
			}
		} catch (IOException exc) {
			throw new RuntimeException(exc);
		} finally {
			Streams.safeClose(input);
		}
	}

	public static final byte[] readStream(InputStream input) {
		return Streams.readStream(input, true);
	}

	public static final ByteBuffer readStream(ReadableByteChannel input) {
		return Streams.readStream(input, true);
	}

	public static final byte[] readStream(InputStream input, boolean closeInput) {
		ByteArrayOutputStream output = new ByteArrayOutputStream(DEFAULT_BUFFER_SIZE);

		boolean success = transfer(input, output, closeInput, false, null, DEFAULT_BUFFER_SIZE, -1);

		if (!success)
			return null;

		return output.toByteArray();
	}

	public static final ByteBuffer readStream(ReadableByteChannel input, boolean closeInput) {
		List<ByteBuffer> buffers = new ArrayList<ByteBuffer>();
		ByteBuffer current = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE);

		try {
			while (true) {
				if (!current.hasRemaining()) {
					current.flip();
					buffers.add(current);
					current = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE);
				}

				if (input.read(current) == -1) {
					current.flip();
					buffers.add(current);
					break;
				}
			}
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		} finally {
			if (closeInput) {
				Streams.safeClose(input);
			}
		}

		int sum = 0;
		for (ByteBuffer bb : buffers)
			sum += bb.remaining();

		ByteBuffer whole = ByteBuffer.allocate(sum);
		for (ByteBuffer bb : buffers)
			whole.put(bb);
		whole.flip();

		return whole;
	}

	/**
	 * WRITE
	 */

	public static final void writeStream(OutputStream output, byte[] data) {
		writeStream(output, data, 64 * 1024);
	}

	public static final void writeStream(OutputStream output, byte[] data, int block) {
		try {
			int offset = 0;

			while (offset != data.length) {
				int remaining = data.length - offset;
				int chunk = Math.min(remaining, block);

				output.write(data, offset, chunk);
				output.flush();

				offset += chunk;
			}
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		} finally {
			Streams.safeClose(output);
		}
	}

	public static final void writeStream(WritableByteChannel output, ByteBuffer data) {
		try {
			while (data.hasRemaining())
				output.write(data);
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		} finally {
			Streams.safeClose(output);
		}
	}

	public static final byte[][] readProcess(Process p) {
		try {
			InputStream out = p.getInputStream();
			InputStream err = p.getErrorStream();

			ByteArrayOutputStream outDst = new ByteArrayOutputStream();
			ByteArrayOutputStream errDst = new ByteArrayOutputStream();

			//

			NonBlockingTransfer outNBT = new NonBlockingTransfer(out, outDst, true, true, null, 8 * 1024, -1);
			NonBlockingTransfer errNBT = new NonBlockingTransfer(err, errDst, true, true, null, 8 * 1024, -1);

			new Thread(outNBT, "asyncTransferOut:" + p.toString()).start();
			new Thread(errNBT, "asyncTransferErr:" + p.toString()).start();

			//

			while (!outNBT.isDone())
				HighLevel.sleep(10);

			while (!errNBT.isDone())
				HighLevel.sleep(10);

			//

			byte[] outRaw = outDst.toByteArray();
			byte[] errRaw = errDst.toByteArray();

			p.waitFor();

			byte[][] std = new byte[2][];
			std[PROCESS_STDOUT] = outRaw;
			std[PROCESS_STDERR] = errRaw;
			return std;
		} catch (InterruptedException exc) {
			exc.printStackTrace();
			return null;
		} finally {
			p.destroy();
		}
	}

	public static final int transferProcess(Process p, OutputStream out, OutputStream err) {
		try {
			asynchronousTransfer(p.getInputStream(), out);
			asynchronousTransfer(p.getErrorStream(), err);

			return p.waitFor();
		} catch (InterruptedException exc) {
			exc.printStackTrace();
			return -1;
		} finally {
			p.destroy();
		}
	}

	private static class NonBlockingTransfer implements Runnable {
		InputStream input;
		OutputStream output;

		boolean closeInput;
		boolean closeOutput;

		TransferListener transferListener;
		int bufferSize;
		int expected;

		NonBlockingTransfer(InputStream input, OutputStream output, boolean closeInput, boolean closeOutput, TransferListener transferListener, int bufferSize, int expected) {
			this.input = input;
			this.output = output;

			this.closeInput = closeInput;
			this.closeOutput = closeOutput;

			this.transferListener = transferListener;
			this.bufferSize = bufferSize;
			this.expected = expected;

			done = false;
		}

		private boolean done;

		public void run() {
			Streams.transfer(input, output, closeInput, closeOutput, transferListener, bufferSize, expected);

			done = true;
		}

		public boolean isDone() {
			return done;
		}
	}

	/**
	 * CLOSE
	 */

	public static final void safeClose(Process proc) {
		if (proc == null) {
			return;
		}

		proc.destroy();
	}

	public static final void safeClose(Closeable io) {
		if (io == null) {
			return;
		}

		try {
			io.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(Connection sql) {
		if (sql == null) {
			return;
		}

		try {
			sql.close();
		} catch (SQLException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(Statement stmt) {
		if (stmt == null) {
			return;
		}

		try {
			stmt.close();
		} catch (SQLException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(ResultSet rs) {
		if (rs == null) {
			return;
		}

		try {
			rs.close();
		} catch (SQLException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(InputStream input) {
		if (input == null) {
			return;
		}

		try {
			input.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(OutputStream output) {
		if (output == null) {
			return;
		}

		try {
			output.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(Reader reader) {
		if (reader == null) {
			return;
		}

		try {
			reader.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(Writer writer) {
		if (writer == null) {
			return;
		}

		try {
			writer.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(DatagramSocket socket) {
		if (socket == null) {
			return;
		}

		socket.close();
	}

	public static final void safeClose(Socket socket) {
		if (socket == null) {
			return;
		}

		try {
			socket.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(ServerSocket serversocket) {
		if (serversocket == null) {
			return;
		}

		try {
			serversocket.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(Channel channel) {
		if (channel == null) {
			return;
		}

		try {
			channel.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(RandomAccessFile raf) {
		if (raf == null) {
			return;
		}

		try {
			raf.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final void safeClose(ZipFile zipFile) {
		if (zipFile == null) {
			return;
		}

		try {
			zipFile.close();
		} catch (IOException exc) {
			// exc.printStackTrace();
		}
	}

	public static final String binaryReadLineAsString(InputStream in) {
		byte[] raw = Streams.binaryReadLineIncluded(in, 4 * 1024);
		if (raw == null)
			return null;

		// must end with "\r\n"
		if ((raw[raw.length - 2] & 0xFF) != '\r')
			throw new IllegalStateException("no eol");
		if ((raw[raw.length - 1] & 0xFF) != '\n')
			throw new IllegalStateException("no eol");

		byte[] stripped = new byte[raw.length - 2];
		System.arraycopy(raw, 0, stripped, 0, stripped.length);
		return Text.utf8(stripped);
	}

	public static final byte[] binaryReadLineIncluded(InputStream in, int upToBytes) {
		byte[] target = new byte[upToBytes];
		int len = binaryReadLineIncludedImpl(in, target.length, target);
		if (len == -1)
			return null;
		return Arrays.copyOf(target, len);
	}

	private static final int binaryReadLineIncludedImpl(InputStream in, int upToBytes, byte[] target) {
		int targetOffset = 0;

		boolean wasReturnChar = false;

		while (true) {
			int b;

			try {
				b = in.read();
			} catch (IOException exc) {
				b = -1;
			}

			if (b == -1) {
				if (targetOffset == 0)
					return -1;
				break;
			}

			if (targetOffset == target.length) {
				return targetOffset; // potential miss
			}
			target[targetOffset++] = (byte) b;

			if (wasReturnChar && b == (byte) '\n') {
				break;
			}

			wasReturnChar = (b == (byte) '\r');
			if (wasReturnChar) {
				continue;
			}

			// last, to ensure '\r' is always followed by next char
			if (targetOffset >= upToBytes) {
				break;
			}
		}

		return targetOffset;
	}
}