/*
 * Created on 15 okt 2008
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import craterstudio.io.Streams;
import craterstudio.time.Clock;
import craterstudio.util.concur.ConcurrentQueue;
import craterstudio.util.HighLevel;

public class AsyncOutputStream extends OutputStream {
	final OutputStream out;
	final ConcurrentQueue<byte[]> queue;
	volatile IOException caught;
	final AtomicInteger buffered;
	final int maxBuffered;

	public AsyncOutputStream(OutputStream out) {
		this(out, 1024 * 1024, 0L);
	}

	public AsyncOutputStream(OutputStream out, int maxBuffered, final long sleepWhenDrained) {
		this.out = out;
		this.queue = new ConcurrentQueue<byte[]>(false);
		this.maxBuffered = maxBuffered;
		this.buffered = new AtomicInteger();

		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					pump(sleepWhenDrained);
				} catch (IOException exc) {
					caught = exc;
				} finally {
					Streams.safeClose(AsyncOutputStream.this.out);

					while (queue.isEmpty()) {
						queue.consume();
					}
				}
			}
		}).start();
	}

	public void onFull(long took) {

	}

	public boolean isFull() {
		return this.buffered.get() >= this.maxBuffered;
	}

	void pump(long sleepWhenDrained) throws IOException {
		while (true) {
			for (int reads = 0; true; reads++) {
				byte[] data;

				if (reads == 0) {
					if ((data = queue.consume()) == null) {
						// eof
						return;
					}
				} else if ((data = queue.poll()) == null) {
					break;
				}

				this.out.write(data);
				buffered.addAndGet(-data.length);
			}

			// queue drained
			this.out.flush();
			HighLevel.sleep(sleepWhenDrained);
		}
	}

	//

	@Override
	public void write(int b) throws IOException {
		this.write(new byte[] { (byte) b }, 0, 1);
	}

	@Override
	public void write(byte[] buf) throws IOException {
		this.write(buf, 0, buf.length);
	}

	@Override
	public synchronized void write(byte[] buf, int off, int len) throws IOException {
		if (this.caught != null) {
			throw this.caught;
		}

		if (this.isFull()) {
			long t0 = Clock.queryMillis();
			int wait = 0, maxWait = 100;
			do {
				HighLevel.sleep(Math.min(++wait, maxWait));
			} while (this.isFull());
			long t1 = Clock.queryMillis();
			this.onFull(t1 - t0);
		}

		while (len > 0) {
			int bytes = Math.min(maxBuffered, len);
			byte[] data = Arrays.copyOfRange(buf, off, off + bytes);
			queue.produce(data);
			this.buffered.addAndGet(bytes);
			off += bytes;
			len -= bytes;
		}
	}

	@Override
	public void flush() throws IOException {
		if (this.caught != null) {
			throw this.caught;
		}
	}

	@Override
	public void close() throws IOException {
		queue.produce(null);
		while (!queue.isEmpty()) {
			if (this.caught != null) {
				throw this.caught;
			}
			HighLevel.sleep(10);
		}
		out.close();
	}
}
