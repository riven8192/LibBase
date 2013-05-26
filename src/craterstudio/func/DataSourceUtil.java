package craterstudio.func;

import java.util.Iterator;
import java.util.NoSuchElementException;

public class DataSourceUtil {
	public static <T> DataSource<T> empty() {
		return new DataSource<T>() {
			@Override
			public T produce() throws NoSuchElementException {
				throw new NoSuchElementException();
			}
		};
	}

	public static <T> DataSource<T> singleton(final T instance) {
		return new DataSource<T>() {
			private boolean spent;

			@Override
			public T produce() throws NoSuchElementException {
				if (spent) {
					throw new NoSuchElementException();
				}
				spent = true;
				return instance;
			}
		};
	}

	public static <T> DataSource<T> chain(final DataSource<DataSource<T>> chain) {
		return new DataSource<T>() {
			private DataSource<T> current = null;

			@Override
			public T produce() throws NoSuchElementException {
				for (;;) {
					if (current == null) {
						current = chain.produce();
					}

					try {
						return current.produce();
					} catch (NoSuchElementException exc) {
						current = null;
					}
				}
			}
		};
	}

	public static <T> DataSource<T> fromIterable(final Iterable<T> it) {
		return fromIterator(it.iterator());
	}

	public static <T> DataSource<T> fromIterator(final Iterator<T> it) {
		return new DataSource<T>() {
			@Override
			public T produce() throws NoSuchElementException {
				if (!it.hasNext()) {
					throw new NoSuchElementException();
				}
				return it.next();
			}
		};
	}

	public static <T> Iterable<T> foreach(final DataSource<T> data) {
		return new Iterable<T>() {
			@Override
			public Iterator<T> iterator() {
				return asIterator(data);
			}
		};
	}

	public static <T> Iterator<T> asIterator(final DataSource<T> data) {
		return new Iterator<T>() {

			private boolean nextSet;
			private T nextVal;

			private void poll(boolean rethrowExc) {
				if (nextSet) {
					throw new IllegalStateException("logic broken");
				}

				try {
					nextVal = data.produce();
					nextSet = true;
				} catch (NoSuchElementException exc) {
					nextVal = null;
					nextSet = false;

					if (rethrowExc) {
						throw exc;
					}
				}
			}

			@Override
			public boolean hasNext() {
				if (!nextSet) {
					poll(false);
				}
				return nextSet;
			}

			@Override
			public T next() {
				if (!nextSet) {
					poll(true);
				}
				if (!nextSet) {
					throw new IllegalStateException("logic broken");
				}

				T val = nextVal;
				nextVal = null;
				nextSet = false;
				return val;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	public static <T> DataSource<T> filter(final DataSource<T> source, final Filter<T> filter) {
		return new DataSource<T>() {
			@Override
			public T produce() throws NoSuchElementException {
				for (T got;;) {
					if (filter.accept(got = source.produce())) {
						return got;
					}
				}
			}
		};
	}
}
