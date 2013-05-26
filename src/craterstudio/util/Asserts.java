/*
 * Created on 22 mrt 2011
 */

package craterstudio.util;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collection;

import javax.swing.SwingUtilities;

public class Asserts {

	public static final boolean assertFalse(boolean val) {
		return assertTrue(null, !val);
	}

	public static final boolean assertTrue(boolean val) {
		return assertTrue(null, val);
	}

	public static final boolean assertEquals(boolean val, boolean comp) {
		return assertEquals(null, val, comp);
	}

	public static final long assertEquals(long val, long comp) {
		return assertEquals(null, val, comp);
	}

	public static final double assertEquals(double val, double comp) {
		return assertEquals(null, val, comp);
	}

	public static final Object assertEquals(Object val, Object comp) {
		return assertEquals(null, val, comp);
	}

	public static final long assertNotEquals(long val, long comp) {
		return assertNotEquals(null, val, comp);
	}

	public static final double assertNotEquals(double val, double comp) {
		return assertNotEquals(null, val, comp);
	}

	//

	public static final <T> T assertNull(T val) {
		return assertNull(null, val);
	}

	public static final <T> T assertNotNull(T val) {
		return assertNotNull(null, val);
	}

	//

	public static final long assertZero(long val) {
		return assertZero(null, val);
	}

	public static final long assertNotZero(long val) {
		return assertNotZero(null, val);
	}

	public static final long assertNegative(long val) {
		return assertNegative(null, val);
	}

	public static final long assertPositive(long val) {
		return assertPositive(null, val);
	}

	public static final long assertAboveZero(long val) {
		return assertAboveZero(null, val);
	}

	public static final long assertLessThan(long val, long compare) {
		return assertLessThan(null, val, compare);
	}

	public static final long assertLessOrEqual(long val, long compare) {
		return assertLessOrEqual(null, val, compare);
	}

	public static final long assertGreaterThan(long val, long compare) {
		return assertGreaterThan(null, val, compare);
	}

	public static final long assertGreaterOrEqual(long val, long compare) {
		return assertGreaterOrEqual(null, val, compare);
	}

	public static final long assertInRange(long val, long min, long max) {
		return assertInRange(null, val, min, max);
	}

	public static final long assertBetween(long val, long min, long max) {
		return assertBetween(null, val, min, max);
	}

	public static final long assertBetweenExcl(long val, long min, long max) {
		return assertBetweenExcl(null, val, min, max);
	}

	public static final void assertOnEDT() {
		assertOnEDT(null);
	}

	public static final void assertNotOnEDT() {
		assertNotOnEDT(null);
	}

	// ----

	public static final boolean assertTrue(String id, boolean val) {
		if (!val)
			raise(id, "was false");
		return val;
	}

	//

	public static final boolean assertNotEquals(String id, boolean val, boolean comp) {
		if (val == comp)
			raise(id, "was equal: " + val + " <> " + comp);
		return val;
	}

	public static final long assertNotEquals(String id, long val, long comp) {
		if (val == comp)
			raise(id, "was equal: " + val + " <> " + comp);
		return val;
	}

	public static final double assertNotEquals(String id, double val, double comp) {
		if (val == comp)
			raise(id, "was equal: " + val + " <> " + comp);
		return val;
	}

	//

	public static final boolean assertEquals(String id, boolean val, boolean comp) {
		if (val != comp)
			raise(id, "was not equal: " + val + " <> " + comp);
		return val;
	}

	public static final long assertEquals(String id, long val, long comp) {
		if (val != comp)
			raise(id, "was not equal: " + val + " <> " + comp);
		return val;
	}

	public static final double assertEquals(String id, double val, double comp) {
		if (val != comp)
			raise(id, "was not equal: " + val + " <> " + comp);
		return val;
	}

	public static final Object assertEquals(String id, Object val, Object comp) {
		if (val == comp)
			return val;
		if ((val == null) != (comp == null))
			raise(id, "was not equal: " + val + " <> " + comp);

		if (val != null && val.getClass() == comp.getClass() && val.getClass().isArray() && val.getClass().getComponentType().isPrimitive()) {
			if (val.getClass() == boolean[].class) {
				if (!Arrays.equals((boolean[]) val, (boolean[]) comp))
					raise(id, "was not equal: " + Arrays.toString((boolean[]) val) + " <> " + Arrays.toString((boolean[]) comp));
			} else if (val.getClass() == byte[].class) {
				if (!Arrays.equals((byte[]) val, (byte[]) comp))
					raise(id, "was not equal: " + Arrays.toString((byte[]) val) + " <> " + Arrays.toString((byte[]) comp));
			} else if (val.getClass() == short[].class) {
				if (!Arrays.equals((short[]) val, (short[]) comp))
					raise(id, "was not equal: " + Arrays.toString((short[]) val) + " <> " + Arrays.toString((short[]) comp));
			} else if (val.getClass() == char[].class) {
				if (!Arrays.equals((char[]) val, (char[]) comp))
					raise(id, "was not equal: " + Arrays.toString((char[]) val) + " <> " + Arrays.toString((char[]) comp));
			} else if (val.getClass() == int[].class) {
				if (!Arrays.equals((int[]) val, (int[]) comp))
					raise(id, "was not equal: " + Arrays.toString((int[]) val) + " <> " + Arrays.toString((int[]) comp));
			} else if (val.getClass() == long[].class) {
				if (!Arrays.equals((long[]) val, (long[]) comp))
					raise(id, "was not equal: " + Arrays.toString((long[]) val) + " <> " + Arrays.toString((long[]) comp));
			} else if (val.getClass() == float[].class) {
				if (!Arrays.equals((float[]) val, (float[]) comp))
					raise(id, "was not equal: " + Arrays.toString((long[]) val) + " <> " + Arrays.toString((float[]) comp));
			} else if (val.getClass() == double[].class) {
				if (!Arrays.equals((double[]) val, (double[]) comp))
					raise(id, "was not equal: " + Arrays.toString((double[]) val) + " <> " + Arrays.toString((double[]) comp));
			}
		}

		if (!((val != null) ? val : comp).equals((val != null) ? comp : val))
			raise(id, "was not equal: " + val + " <> " + comp);
		return val;
	}

	// ----------------

	public static final <T> T assertNull(String id, T val) {
		if (val != null)
			raise(id, "was not null");
		return val;
	}

	public static final <T> T assertNotNull(String id, T val) {
		if (val == null)
			raise(id, "was null");
		return val;
	}

	//

	public static final long assertZero(String id, long val) {
		if (val != 0)
			raise(id, "was not zero: " + val);
		return val;
	}

	public static final long assertNotZero(String id, long val) {
		if (val == 0)
			raise(id, "was zero: " + val);
		return val;
	}

	public static final long assertNegative(String id, long val) {
		if (val >= 0)
			raise(id, "was not negative: " + val);
		return val;
	}

	public static final long assertPositive(String id, long val) {
		if (val < 0)
			raise(id, "was not positive: " + val);
		return val;
	}

	public static final long assertAboveZero(String id, long val) {
		if (val <= 0)
			raise(id, "was not above zero: " + val);
		return val;
	}

	public static final long assertLessThan(String id, long val, long compare) {
		if (val >= compare)
			raise(id, "too large: " + val + " >= " + compare);
		return val;
	}

	public static final long assertLessOrEqual(String id, long val, long compare) {
		if (val > compare)
			raise(id, "too large: " + val + " > " + compare);
		return val;
	}

	public static final long assertGreaterThan(String id, long val, long compare) {
		if (val <= compare)
			raise(id, "too small: " + val + " <= " + compare);
		return val;
	}

	public static final long assertGreaterOrEqual(String id, long val, long compare) {
		if (val < compare)
			raise(id, "too small: " + val + " < " + compare);
		return val;
	}

	// --

	public static final long assertInRange(String id, long val, long minIncl, long maxExcl) {
		assertLessThan("illegal range =>", minIncl, maxExcl);

		if (val < minIncl || val >= maxExcl)
			raise(id, "not in range: " + minIncl + " (incl) .. " + val + " .. " + maxExcl + " (excl)");
		return val;
	}

	public static final long assertBetween(String id, long val, long min, long max) {
		assertLessOrEqual("illegal range => ", min, max);

		if (val < min || val > max)
			raise(id, "not in range: " + min + " (incl) .. " + val + " .. " + max + " (incl)");
		return val;
	}

	public static final long assertBetweenExcl(String id, long val, long min, long max) {
		assertLessThan("illegal range => ", min, max);

		if (val <= min || val >= max)
			raise(id, "not in range: " + min + " (excl) .. " + val + " .. " + max + " (excl)");
		return val;
	}

	public static final void assertOnEDT(String id) {
		if (!SwingUtilities.isEventDispatchThread())
			raise(id, "must run on event-dispatch-thread");
	}

	public static final void assertNotOnEDT(String id) {
		if (SwingUtilities.isEventDispatchThread())
			raise(id, "must not run on event-dispatch-thread");
	}

	public static final <T> T assertNotEmpty(T t, String msg) {
		if (t == null)
			throw new IllegalStateException(msg + ": NULL EMPTY");

		if (t instanceof String) {
			if (((String) t).trim().length() == 0)
				throw new IllegalStateException(msg + ": " + t + " STRING EMPTY");
			return t;
		}

		if (t instanceof Collection<?>) {
			if (((Collection<?>) t).size() == 0)
				throw new IllegalStateException(msg + ": " + t + " COLLECTION EMPTY");
			return t;
		}

		if (t.getClass().isArray()) {
			if (Array.getLength(t) == 0)
				throw new IllegalStateException(msg + ": " + t + " ARRAY EMPTY");
			return t;
		}

		if (t instanceof Number) {
			if ((t instanceof Byte) && ((Byte) t).byteValue() == 0)
				throw new IllegalArgumentException(msg + ": BYTE ZERO");
			if ((t instanceof Short) && ((Short) t).shortValue() == 0)
				throw new IllegalArgumentException(msg + ": SHORT ZERO");
			if ((t instanceof Character) && ((Character) t).charValue() <= ' ') // whitespace
				throw new IllegalArgumentException(msg + ": CHAR EMPTY");
			if ((t instanceof Integer) && ((Integer) t).intValue() == 0)
				throw new IllegalArgumentException(msg + ": INT ZERO");
			if ((t instanceof Long) && ((Long) t).longValue() == 0)
				throw new IllegalArgumentException(msg + ": LONG ZERO");
			if ((t instanceof Float) && ((Float) t).floatValue() == 0.0f)
				throw new IllegalArgumentException(msg + ": FLOAT ZERO");
			if ((t instanceof Double) && ((Double) t).doubleValue() == 0.0)
				throw new IllegalArgumentException(msg + ": DOUBLE ZERO");
			return t;
		}

		if (t instanceof Boolean) {
			if (((Boolean) t).booleanValue() == false)
				throw new IllegalArgumentException(msg + ": BOOLEAN ZERO");
			return t;
		}

		return t;
	}

	// --------------

	private static final void raise(String id, String reason) {
		String name = (id == null ? "value" : ("'" + id + "'"));
		throw new IllegalStateException(name + " " + reason);
	}
}
