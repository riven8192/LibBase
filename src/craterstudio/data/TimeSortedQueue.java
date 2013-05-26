/*
 * Created on 15 apr 2011
 */

package craterstudio.data;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.PriorityQueue;

import craterstudio.func.Callback;
import craterstudio.func.Condition;
import craterstudio.func.Filter;
import craterstudio.func.OrderComparator;
import craterstudio.util.HighLevel;

public class TimeSortedQueue<T> {
	private final PriorityQueue<Slot<T>> queue;

	public TimeSortedQueue() {

		OrderComparator<Slot<T>> comparator = new OrderComparator<Slot<T>>() {
			@Override
			public boolean isOrdered(Slot<T> o1, Slot<T> o2) {
				return o1.time <= o2.time;
			}

			@Override
			public boolean areEqual(Slot<T> o1, Slot<T> o2) {
				return false;
			}
		};

		this.queue = new PriorityQueue<Slot<T>>(11, comparator);
	}

	public void spawnPollLoop(final Callback<T> callback, final long pause) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				runPollLoop(callback, pause);
			}
		}).start();
	}

	public void runPollLoop(Callback<T> callback, long pause) {
		while (true) {
			try {
				callback.callback(this.pop(pause));
			} catch (Throwable t) {
				t.printStackTrace();
			}
		}
	}

	public static class Slot<Q> {
		public final long time;
		public final Q item;

		public Slot(long time, Q item) {
			this.time = time;
			this.item = item;
		}

		@Override
		public String toString() {
			return "Slot[time=" + time + "]";
		}
	}

	// --

	long now() {
		return System.currentTimeMillis();
	}

	public int size() {
		synchronized (this.queue) {
			return this.queue.size();
		}
	}

	public void insert(long time, T item) {
		synchronized (this.queue) {
			if (this.queue.add(new Slot<T>(time, item))) {
				this.queue.notifyAll();
			} else {
				throw new IllegalStateException();
			}
		}
	}

	public void clear() {
		synchronized (this.queue) {
			this.queue.clear();
		}
	}

	private final boolean hasItem(long now) {
		Slot<T> peeked = TimeSortedQueue.this.peekQueue();
		return (peeked != null && peeked.time <= now);
	}

	private final Condition popCondition = new Condition() {
		@Override
		public boolean pass() {
			return hasItem(now());
		}
	};

	public T pop(long pollInterval) {
		HighLevel.sleep(pollInterval, popCondition, true);
		return TimeSortedQueue.this.pollQueue().item;
	}

	public T poll(long now) {
		return this.hasItem(now) ? TimeSortedQueue.this.pollQueue().item : null;
	}

	public Slot<T> pollSlot(long now) {
		return this.hasItem(now) ? TimeSortedQueue.this.pollQueue() : null;
	}

	private Slot<T> peekQueue() {
		synchronized (this.queue) {
			return this.queue.peek();
		}
	}

	private Slot<T> pollQueue() {
		synchronized (this.queue) {
			return this.queue.poll();
		}
	}

	public List<T> drain() {
		List<T> list = new ArrayList<>();
		synchronized (this.queue) {
			while (true) {
				Slot<T> slot = this.pollQueue();
				if (slot == null) {
					break;
				}
				list.add(slot.item);
			}
		}
		return list;
	}

	public int preempt(T item) {
		int count = 0;
		synchronized (this.queue) {
			Iterator<Slot<T>> it = this.queue.iterator();
			while (it.hasNext()) {
				if (item == it.next().item) {
					it.remove();
					count++;
				}
			}
		}
		return count;
	}

	public int preempt(Filter<T> filter) {
		int count = 0;
		synchronized (this.queue) {
			Iterator<Slot<T>> it = this.queue.iterator();
			while (it.hasNext()) {
				if (filter.accept(it.next().item)) {
					it.remove();
					count++;
				}
			}
		}
		return count;
	}
}
