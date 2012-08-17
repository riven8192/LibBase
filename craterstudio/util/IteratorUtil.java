/*
 * Created on 22 aug 2008
 */

package craterstudio.util;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;

import craterstudio.func.Filter;
import craterstudio.func.Operator;
import craterstudio.func.Transformer;

public class IteratorUtil {
	public static <E> Iterable<E> emptyIterable(final Class<E> clzz) {
		return new Iterable<E>() {
			@Override
			public Iterator<E> iterator() {
				return IteratorUtil.emptyIterator(clzz);
			}
		};
	}

	public static <E> Iterable<E> singletonIterable(final E e) {
		return new Iterable<E>() {
			@Override
			public Iterator<E> iterator() {
				return new Iterator<E>() {
					boolean got = false;

					@Override
					public boolean hasNext() {
						return !this.got;
					}

					@Override
					public E next() {
						if (this.got)
							throw new NoSuchElementException();
						this.got = true;
						return e;
					}

					@Override
					public void remove() {
						throw new UnsupportedOperationException();
					}
				};
			}
		};
	}

	public static <E> Iterator<E> singletonIterator(final E e) {
		return singletonIterable(e).iterator();
	}

	public static <E> Iterator<E> operator(final Iterator<E> iterator, final Operator<E> operator) {
		return new Iterator<E>() {
			private E curr;
			private boolean isCurrValid;

			@Override
			public boolean hasNext() {
				return iterator.hasNext();
			}

			@Override
			public E next() {
				curr = iterator.next();
				isCurrValid = true;
				operator.operate(curr);
				return curr;
			}

			@Override
			public void remove() {
				if (!isCurrValid) {
					throw new IllegalStateException();
				}
				iterator.remove();
				this.isCurrValid = false;
				this.curr = null;
			}
		};
	}

	//

	public static <O, I> Iterator<O> transform(final Iterator<I> iterator, final Transformer<I, O> transformer) {
		return new Iterator<O>() {
			private I curr;
			private boolean isCurrValid;

			@Override
			public boolean hasNext() {
				return iterator.hasNext();
			}

			@Override
			public O next() {
				curr = iterator.next();
				isCurrValid = true;

				return transformer.transform(curr);
			}

			@Override
			public void remove() {
				if (!isCurrValid) {
					throw new IllegalStateException();
				}
				iterator.remove();
				this.isCurrValid = false;
				this.curr = null;
			}
		};
	}

	public static <E> Collection<E> fill(Iterator<E> it, Collection<E> col) {
		while (it.hasNext())
			col.add(it.next());
		return col;
	}

	//

	public static <E> Iterator<E> chain(final Iterator<Iterator<E>> iterators) {
		return new Iterator<E>() {
			Iterator<E> current;

			@Override
			public boolean hasNext() {
				do {
					if (current == null) {
						if (!iterators.hasNext())
							return false;
						current = iterators.next();
					}

					if (current.hasNext())
						return true;

					current = null;
				} while (true);
			}

			@Override
			public E next() {
				if (!this.hasNext())
					throw new NoSuchElementException();
				return current.next();
			}

			@Override
			public void remove() {
				current.remove();
			}
		};
	}

	public static <E> Iterator<E> emptyIterator(Class<E> clzz) {
		return new Iterator<E>() {
			@Override
			public boolean hasNext() {
				return false;
			}

			@Override
			public E next() {
				throw new NoSuchElementException();
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	public static <E> Iterator<E> removingIterator(final Iterator<E> it) {
		return new Iterator<E>() {
			@Override
			public boolean hasNext() {
				return it.hasNext();
			}

			@Override
			public E next() {
				E e = it.next();
				it.remove();
				return e;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	public static <E> Iterator<E> filter(final Iterator<E> iterator, final Filter<E> filter) {
		return new Iterator<E>() {
			private E next;
			private boolean isNextValid;
			private boolean isRemoveValid;

			@Override
			public boolean hasNext() {
				if (isNextValid) {
					return true;
				}

				while (true) {
					if (!iterator.hasNext()) {
						return false;
					}

					E maybe = iterator.next();
					if (filter.accept(maybe)) {
						next = maybe;
						isNextValid = true;
						return true;
					}
				}
			}

			@Override
			public E next() {
				isRemoveValid = false;

				if (isNextValid) {
					isNextValid = false;
					isRemoveValid = true;
					return next;
				}

				if (!this.hasNext())
					throw new NoSuchElementException();

				isRemoveValid = true;
				return next;
			}

			@Override
			public void remove() {
				if (isRemoveValid) {
					throw new IllegalStateException();
				}
				iterator.remove();
				isRemoveValid = false;
				this.next = null;
			}
		};
	}

	public static final <T> Iterator<T> iterator(final T[] arr, final int off, final int len) {
		return new Iterator<T>() {
			private int index = -1;

			@Override
			public boolean hasNext() {
				return (index + 1 < len);
			}

			@Override
			public T next() {
				if ((index += 1) >= len)
					throw new NoSuchElementException();
				return arr[off + index];
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	public static final <T> Iterator<T> iterator(final T... arr) {
		return new Iterator<T>() {
			private int index = -1;

			@Override
			public boolean hasNext() {
				return (index + 1 < arr.length);
			}

			@Override
			public T next() {
				if ((index += 1) >= arr.length)
					throw new NoSuchElementException();
				return arr[index];
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	public static final <T> Iterable<T> foreach(final T... arr) {
		return new Iterable<T>() {
			@Override
			public Iterator<T> iterator() {
				return IteratorUtil.iterator(arr);
			}
		};
	}

	public static final <T> Iterable<T> foreach(final Iterator<T> it) {
		return new Iterable<T>() {
			@Override
			public Iterator<T> iterator() {
				return it;
			}
		};
	}

	public static final <T> Iterable<T> foreach(final Enumeration<T> enume) {
		Iterator<T> iter = new Iterator<T>() {
			@Override
			public boolean hasNext() {
				return enume.hasMoreElements();
			}

			@Override
			public T next() {
				return enume.nextElement();
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};

		return foreach(iter);
	}
}
