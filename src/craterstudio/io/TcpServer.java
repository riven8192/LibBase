/*
 * Created on Apr 17, 2012
 */

package craterstudio.io;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;

import craterstudio.func.Callback;
import craterstudio.util.HighLevel;

public class TcpServer {

	public static void listen(ServerSocket ss, Callback<Socket> handler) {
		while (true) {
			try {
				handler.callback(ss.accept());
			} catch (IOException exc) {
				exc.printStackTrace();
				HighLevel.sleep(1000);
			}
		}
	}

	public static void listen(final ServerSocket ss, final Callback<Socket> handler, final ExecutorService service) {
		listen(ss, handler, service, true);
	}

	public static void listen(final ServerSocket ss, final Callback<Socket> handler, final ExecutorService service, final boolean doClose) {
		service.submit(new Runnable() {
			@Override
			public void run() {
				listen(ss, new Callback<Socket>() {
					@Override
					public void callback(final Socket client) {
						if (client instanceof SSLSocket) {
							// disable SSL renegotiation
							final SSLSocket ssl = (SSLSocket) client;
							ssl.addHandshakeCompletedListener(new HandshakeCompletedListener() {
								@Override
								public void handshakeCompleted(HandshakeCompletedEvent event) {
									ssl.setEnabledCipherSuites(new String[0]);
								}
							});
						}

						service.submit(new Runnable() {
							@Override
							public void run() {
								try {
									handler.callback(client);
								} catch (Exception exc) {
									exc.printStackTrace();
								} finally {
									if (doClose) {
										Streams.safeClose(client);
									}
								}
							}
						});
					}
				});
			}
		});
	}

	public static ExecutorService pool(int threadCount, int idleTimeout, final long stackSize) {
		final ThreadFactory threadFactory = new ThreadFactory() {

			final AtomicLong nameCounter = new AtomicLong();

			@Override
			public Thread newThread(Runnable task) {
				return new Thread( //
				   Thread.currentThread().getThreadGroup(), //
				   task, "TCP-Worker-" + nameCounter.incrementAndGet(), //
				   stackSize //
				);
			}
		};

		return new ThreadPoolExecutor( //
		   0, // core threads
		   threadCount, // max threads
		   idleTimeout, // idle
		   TimeUnit.MILLISECONDS, // time unit
		   new SynchronousQueue<Runnable>(), // queue
		   threadFactory //
		);
	}
}
