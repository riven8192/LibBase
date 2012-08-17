/*
 * Created on 20 nov 2009
 */

package craterstudio.util.concur;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import craterstudio.util.HighLevel;

public class LockfreeThreadPool implements Executor {
	final static ThreadMXBean tmxb;
	static {
		ThreadMXBean bean;
		try {
			bean = ManagementFactory.getThreadMXBean();
			bean.setThreadCpuTimeEnabled(true);
		} catch (Exception exc) {
			bean = null;
		}

		tmxb = bean;
	}

	final SimpleBlockingQueue<Runnable> taskQueue;
	final int maxWorkers;
	final Semaphore potentialWorkersLeft;
	final AwaitZeroLatch shutdownLatch;
	volatile boolean isShutdown;
	final long workerTimeout;
	public boolean verbose = true;
	final static long monitor_queue_delay = 100L;
	final static long enough_workers_delay = 1000L;

	public LockfreeThreadPool() {
		this(Runtime.getRuntime().availableProcessors());
	}

	public LockfreeThreadPool(double processorFactor) {
		this((int) Math.ceil(Runtime.getRuntime().availableProcessors()
				* processorFactor));
	}

	public LockfreeThreadPool(int maxWorkers) {
		this(maxWorkers, 60 * 1000);
	}

	public LockfreeThreadPool(int maxWorkers, long workerTimeout) {
		if (maxWorkers <= 0)
			throw new IllegalStateException("invalid amount of workers: "
					+ maxWorkers);
		if (maxWorkers <= 0)
			throw new IllegalStateException("invalid worker timeout: "
					+ workerTimeout);

		this.taskQueue = new SimpleBlockingQueue<Runnable>();
		this.maxWorkers = maxWorkers;

		this.shutdownLatch = new AwaitZeroLatch(1);

		this.potentialWorkersLeft = new Semaphore(maxWorkers + 1);
		this.workerTimeout = workerTimeout;

		this.isShutdown = false;

		this.setWorkerFactory(null);
		new Thread(this.new AsyncWorkerCreater()).start();
	}

	public int maxWorkers() {
		return this.maxWorkers;
	}

	/**
	 * Rather obvious, except that it returns -1 once shutdown and all workers
	 * are terminated.
	 */

	public int countWorkers() {
		return this.maxWorkers - this.potentialWorkersLeft.availablePermits();
	}

	public boolean isTerminated() {
		return this.countWorkers() == -1;
	}

	@Override
	public void execute(Runnable command) {
		this.putTask(command);
	}

	public void waitForBarrier() {
		this.barrier(this.maxWorkers);
	}

	public void barrier(int concurrent) {
		final CyclicBarrier barrier = new CyclicBarrier(1 + concurrent);

		Runnable block = new Runnable() {
			@Override
			public void run() {
				if (awaitBarrier(barrier) == 0) {
					// if (taskQueue.size() > 0)
					// throw new IllegalStateException();
				}
			}
		};

		for (int i = 0; i < concurrent; i++) {
			this.putTask(block);
		}

		block.run();
	}

	static int awaitBarrier(CyclicBarrier barrier) {
		do {
			try {
				int a = barrier.await();
				System.err.println(" b:" + a + " (" + Thread.currentThread()
						+ ")");

				return a;
			} catch (BrokenBarrierException exc) {
				exc.printStackTrace();
			} catch (InterruptedException exc) {
				continue;
			}
		} while (true);
	}

	public void putTask(Runnable task) {
		if (task == null) {
			throw new NullPointerException();
		}

		if (this.isShutdown && task != TERMINATE_WORKER) {
			throw new IllegalStateException("shutdown");
		}

		this.taskQueue.put(task);
	}

	public void shutdown(boolean flushTaskQueue, boolean waitFor) {
		if (this.isShutdown) {
			throw new IllegalStateException();
		}

		this.isShutdown = true;

		if (flushTaskQueue) {
			// flush the task queue
			this.taskQueue.clear();
		}

		int count = Math.max(10, this.countWorkers() * 10);
		for (int i = 0; i < count; i++) {
			this.putTask(TERMINATE_WORKER);
		}

		if (waitFor) {
			try {
				this.shutdownLatch.await();
			} catch (InterruptedException exc) {
				throw new IllegalStateException(exc);
			}
		}
	}

	Runnable takeTask(long msTimeout) {
		return taskQueue.poll(msTimeout);
	}

	volatile ThreadFactory factory;

	public void setWorkerFactory(ThreadFactory factory) {
		if (factory == null) {
			factory = new ThreadFactory() {
				@Override
				public Thread newThread(Runnable r) {
					return new Thread(r);
				}
			};
		}

		this.factory = factory;
	}

	public void setWorkerFactory(final long stacksize) {
		this.setWorkerFactory(new ThreadFactory() {

			@Override
			public Thread newThread(Runnable task) {
				return new Thread(null, task, "httpworker", stacksize);
			}
		});
	}

	class AsyncWorkerCreater implements Runnable {
		@Override
		public void run() {
			LockfreeThreadPool self = LockfreeThreadPool.this;

			while (!self.isShutdown || !self.taskQueue.isEmpty()) {
				try {
					HighLevel.sleep(monitor_queue_delay);

					if (self.taskQueue.isEmpty())
						continue;
					if (!self.potentialWorkersLeft.tryAcquire(
							enough_workers_delay, TimeUnit.MILLISECONDS))
						continue;

					self.factory.newThread(new Worker()).start();
				} catch (InterruptedException exc) {
					throw new IllegalStateException(exc);
				}
			}

			self.shutdownLatch.decrement();
		}
	}

	protected void onSpawnedWorker(int workerCount, int queueSize) {
		//
	}

	protected void onTerminatedWorker(int workerCount, long duration,
			long cpuTimeNanos) {
		//
	}

	class Worker implements Runnable {
		@Override
		public void run() {
			LockfreeThreadPool self = LockfreeThreadPool.this;

			long timeStarted = System.currentTimeMillis();

			int workers;

			workers = self.shutdownLatch.increment() - 1;
			onSpawnedWorker(workers, self.taskQueue.size());

			while (true) {
				Runnable task = self.takeTask(self.workerTimeout);

				if (task == null) // no task available within specified timeout
				{
					break;
				}

				if (task == TERMINATE_WORKER) // request for termination
				{
					break;
				}

				try {
					task.run();
				} catch (Throwable exc) {
					exc.printStackTrace();
				}
			}

			self.potentialWorkersLeft.release();

			workers = self.shutdownLatch.decrement() - 1;

			long timeFinished = System.currentTimeMillis();
			long ns = tmxb == null ? -1L : tmxb.getThreadCpuTime(Thread
					.currentThread().getId());
			onTerminatedWorker(workers, timeFinished - timeStarted, ns);
		}
	}

	static final Runnable TERMINATE_WORKER;

	static {
		TERMINATE_WORKER = new Runnable() {
			public void run() {
				// dummy
			}
		};
	}
}