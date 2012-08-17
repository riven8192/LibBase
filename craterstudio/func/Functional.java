/*
 * Created on 20 jul 2010
 */

package craterstudio.func;

import java.util.Iterator;

import craterstudio.util.Asserts;
import craterstudio.util.IteratorUtil;

public class Functional {
	public static <T> ObjectStream<T> emptyStream() {
		return new ObjectStream<T>() {
			@Override
			public T next() {
				return (T) ObjectStream.END_OF_STREAM;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	public static <T> Stream<T> emptyStream2() {
		return new Stream<T>() {
			public T poll() {
				return null;
			}

			@Override
			public boolean reachedEnd() {
				return true;
			}
		};
	}

	/**
	 * Filter items from the view of the returned Iterable<T>
	 */

	public static <T> Iterable<T> filter(Iterable<T> iterable, Filter<T> filter) {
		Asserts.assertNotNull(iterable);
		Asserts.assertNotNull(filter);

		final ObjectStream<T> stream = ObjectStreamIterable.stream(iterable.iterator());
		return IteratorUtil.foreach(ObjectStreamIterable.iterator(filter(stream, filter)));
	}

	public static <T> ObjectStream<T> filter(final ObjectStream<T> stream, final Filter<T> filter) {
		Asserts.assertNotNull(stream);
		Asserts.assertNotNull(filter);

		return new ObjectStream<T>() {
			@Override
			public T next() {
				for (;;) {
					T item = stream.next();
					if (item == ObjectStream.END_OF_STREAM)
						return (T) ObjectStream.END_OF_STREAM;

					if (filter.accept(item)) {
						return item;
					}
				}
			}

			@Override
			public void remove() {
				stream.remove();
			}
		};
	}

	/**
	 * Transforms Iterable<I> into Iterable<O> using a Transformer<I, O>
	 */

	public static <I, O> Iterable<O> transform(Iterable<I> iterable, final Transformer<I, O> transformer) {
		Asserts.assertNotNull(iterable);
		Asserts.assertNotNull(transformer);

		final ObjectStream<I> stream = ObjectStreamIterable.stream(iterable.iterator());
		return IteratorUtil.foreach(ObjectStreamIterable.iterator(transform(stream, transformer)));
	}

	public static <I, O> ObjectStream<O> transform(final ObjectStream<I> stream, final Transformer<I, O> transformer) {
		return new ObjectStream<O>() {
			@Override
			public O next() {
				I item = stream.next();
				if (item == ObjectStream.END_OF_STREAM)
					return (O) ObjectStream.END_OF_STREAM;
				return transformer.transform(item);
			}

			@Override
			public void remove() {
				stream.remove();
			}
		};
	}

	/**
	 * Consumes (removes) all items while iterating<T>
	 */

	public static <T> Iterable<T> consume(Iterable<T> iterable) {
		Asserts.assertNotNull(iterable);

		final ObjectStream<T> stream = ObjectStreamIterable.stream(iterable.iterator());
		return IteratorUtil.foreach(ObjectStreamIterable.iterator(consume(stream)));
	}

	public static <T> ObjectStream<T> consume(final ObjectStream<T> stream) {
		Asserts.assertNotNull(stream);

		return new ObjectStream<T>() {
			@Override
			public T next() {
				T item = stream.next();
				if (item == ObjectStream.END_OF_STREAM)
					return (T) ObjectStream.END_OF_STREAM;
				stream.remove();
				return item;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	/**
	 * Performs a callback on each element-visit, and each element removal
	 */

	public static <T> Iterable<T> eventHook(final Iterable<T> iterable, final Operator<T> onVisit, final Operator<T> onRemove) {
		if (iterable == null)
			throw new NullPointerException();
		if (onVisit == null && onRemove == null)
			throw new NullPointerException("must specify either onVisit, onRemove or both");

		return new Iterable<T>() {
			@Override
			public Iterator<T> iterator() {
				final Iterator<T> iterator = iterable.iterator();

				return new Iterator<T>() {
					@Override
					public boolean hasNext() {
						return iterator.hasNext();
					}

					@Override
					public T next() {
						this.current = iterator.next();
						if (onVisit != null)
							onVisit.operate(this.current);
						return this.current;
					}

					@Override
					public void remove() {
						iterator.remove();
						if (onRemove != null)
							onRemove.operate(this.current);
					}

					//

					private T current;
				};
			}
		};
	}
}