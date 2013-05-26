/*
 * Created on Aug 7, 2005
 */
package craterstudio.util;

import java.util.List;
import java.util.ArrayList;

public class Pool<T> {
	private final int maxSize;

	Pool() {
		this.creator = null;
		this.pool = null;
		this.maxSize = -1;
	}

	public Pool(PoolHandler<T> creator) {
		this(creator, 0, -1);
	}

	public Pool(PoolHandler<T> creator, int maxSize) {
		this(creator, 0, maxSize);
	}

	public Pool(PoolHandler<T> creator, int initSize, int maxSize) {
		this.creator = creator;
		this.maxSize = maxSize;

		this.pool = new ArrayList<T>();
		for (int i = 0; i < initSize; i++) {
			pool.add(this.create());
		}
	}

	private T create() {
		T item = creator.create();
		creator.clean(item);
		createCount++;
		return item;
	}

	private int createCount;
	private final List<T> pool;
	private final PoolHandler<T> creator;

	/**
	 * Tries to take an object from the pool, otherwise creates a new one.
	 */

	public T aquire() {
		return pool.isEmpty() ? this.create() : ListUtil.removeLast(pool);
	}

	/**
	 * Adds the object to the pool, if it fits.
	 */

	public T release(T item) {
		if (item == null) {
			return null;
		}

		creator.clean(item);

		if (true) {
			this.verifyUniqueRelease(item);
		}

		if (maxSize == -1 || (maxSize != -1 && pool.size() < maxSize)) {

			pool.add(item);
		}

		return null;
	}

	private void verifyUniqueRelease(T toAdd) {
		// don't use pool.contains() because it uses obj.equals(item), which might
		// return true
		for (T item : pool) {
			if (toAdd == item) {
				throw new IllegalStateException();
			}
		}
	}

	/**
	 * Ensure the pool holds this many objects.
	 */

	public void ensure(int amount) {
		if (maxSize != -1 && amount > maxSize)
			throw new IllegalStateException("Amount (" + amount + ") is larger than the maximum size (" + maxSize + ")");

		int create = pool.size() - amount;
		for (int i = 0; i < create; i++) {
			pool.add(this.create());
		}
	}

	/**
	 * Flushes the pool.
	 */

	public void flush() {
		pool.clear();
	}

	public int createdObjectsCount() {
		return this.createCount;
	}

	public int linkedObjectsCount() {
		return pool.size();
	}

	/**
    * 
    */

	public final Pool<T> asThreadSafePool() {
		final Pool<T> backing = this;

		return new Pool<T>() {
			private final Object lock = new Object();

			public T aquire() {
				synchronized (lock) {
					return backing.aquire();
				}
			}

			public T release(T t) {
				synchronized (lock) {
					return backing.release(t);
				}
			}

			public void ensure(int amount) {
				synchronized (lock) {
					backing.ensure(amount);
				}
			}

			public void flush() {
				synchronized (lock) {
					backing.flush();
				}
			}

			public int createdObjectsCount() {
				synchronized (lock) {
					return backing.createdObjectsCount();
				}
			}

			public int linkedObjectsCount() {
				synchronized (lock) {
					return backing.linkedObjectsCount();
				}
			}
		};
	}
}