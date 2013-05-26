/*
 * Created on 3 feb 2009
 */

package craterstudio.util;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.RandomAccess;

public class ListUtil {
	public static <T> T getFirstIfAny(List<T> list) {
		if (list.isEmpty()) {
			return null;
		}

		if (list instanceof Deque<?>) {
			return ((Deque<T>) list).getFirst();
		}

		if (list instanceof RandomAccess) {
			return list.get(0);
		}

		// better way?
		return list.get(0);
	}

	public static <T> T getRandom(List<T> list, Random random) {
		if (list.isEmpty()) {
			throw new NoSuchElementException();
		}
		
		return list.get(random.nextInt(list.size()));
	}

	public static <T> T getLast(List<T> list) {
		if (list.isEmpty()) {
			throw new NoSuchElementException();
		}

		if (list instanceof Deque<?>) {
			return ((Deque<T>) list).getLast();
		}

		if (list instanceof RandomAccess) {
			return list.get(list.size() - 1);
		}

		// better way?
		return list.get(list.size() - 1);
	}

	public static <T> T getLastIfAny(List<T> list) {
		if (list.isEmpty()) {
			return null;
		}

		if (list instanceof Deque<?>) {
			return ((Deque<T>) list).getLast();
		}

		if (list instanceof RandomAccess) {
			return list.get(list.size() - 1);
		}

		// better way?
		return list.get(list.size() - 1);
	}

	public static <T> T removeLast(List<T> list) {
		if (list.isEmpty()) {
			throw new NoSuchElementException();
		}

		if (list instanceof Deque<?>) {
			return ((Deque<T>) list).removeLast();
		}

		if (list instanceof RandomAccess) {
			return list.remove(list.size() - 1);
		}

		// better way?
		return list.remove(list.size() - 1);
	}

	public static <T> List<T> duplicate(List<T> values, int times) {
		List<T> result = new ArrayList<T>();
		for (int i = 0; i < times; i++)
			result.addAll(values);
		return result;
	}

	public static <T> T[] toArray(Class<T> clazz, Iterable<T> chain) {
		List<T> list = fill(chain);
		T[] arr = (T[]) Array.newInstance(clazz, list.size());
		return list.toArray(arr);
	}

	public static <T> List<T> refill(List<T> list, Iterable<T> source) {
		list.clear();
		for (T t : source)
			list.add(t);
		return list;
	}

	public static <T> List<T> fill(Iterable<T> source) {
		List<T> copy = new ArrayList<T>();
		for (T t : source)
			copy.add(t);
		return copy;
	}

	public static <T> List<T> filter(Iterable<T> list, ListFilter<T> filter) {
		List<T> copy = new ArrayList<T>();
		for (T t : list)
			if (filter.accept(t))
				copy.add(t);
		return copy;
	}

	public static <T> List<T> reverse(List<T> list) {
		List<T> copy = fill(list);
		Collections.reverse(copy);
		return copy;
	}

	public static <T> boolean containsAny(List<T> a, List<T> b) {
		for (T item : b)
			if (a.contains(item))
				return true;
		return false;
	}

	public static <T> boolean containsSequence(List<T> a, List<T> b) {
		int remaining = a.size() - b.size();

		outer: for (int i = 0; i <= remaining; i++) {
			for (int k = 0; k < b.size(); k++)
				if (!a.get(i + k).equals(b.get(k)))
					continue outer;
			return true;
		}

		return false;
	}

	public static <T> boolean containsUnorderedSequence(List<T> a, List<T> b) {
		int remaining = a.size() - b.size();

		for (int i = 0; i < remaining; i++)
			if (a.subList(i, i + b.size()).containsAll(b))
				return true;

		return false;
	}

	public static <T> boolean containsInOrder(List<T> a, List<T> b) {
		int lastMatch = -1;

		for (int i = 0; i < b.size(); i++) {
			T find = b.get(i);
			boolean found = false;

			for (int k = lastMatch + 1; k < a.size(); k++) {
				if (a.get(k).equals(find)) {
					lastMatch = k;
					found = true;
					break;
				}
			}

			if (!found) {
				return false;
			}
		}

		return true;
	}
}
