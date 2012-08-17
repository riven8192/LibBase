/*
 * Created on 20-sep-2007
 */

package craterstudio.bytes;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.MappedByteBuffer;
import java.security.AccessController;
import java.security.PrivilegedAction;

import craterstudio.data.tuples.Pair;

import sun.misc.Unsafe;

public class NativeHacks {
	private final static Unsafe unsafe;
	private static long addressOffset;
	private static long positionOffset;
	private static long limitOffset;
	private static long capacityOffset;

	public static final long WORD_SIZE_BITS, OBJECT_HEADER_SIZE;

	public static final long BYTE_ARRAY_BASE_OFFSET;
	public static final long SHORT_ARRAY_BASE_OFFSET;
	public static final long INT_ARRAY_BASE_OFFSET;
	public static final long LONG_ARRAY_BASE_OFFSET;
	public static final long FLOAT_ARRAY_BASE_OFFSET;
	public static final long DOUBLE_ARRAY_BASE_OFFSET;
	public static final long OBJECT_ARRAY_BASE_OFFSET;

	public static final long BYTE_ARRAY_LENGTH_OFFSET;
	public static final long SHORT_ARRAY_LENGTH_OFFSET;
	public static final long INT_ARRAY_LENGTH_OFFSET;
	public static final long LONG_ARRAY_LENGTH_OFFSET;
	public static final long FLOAT_ARRAY_LENGTH_OFFSET;
	public static final long DOUBLE_ARRAY_LENGTH_OFFSET;
	public static final long OBJECT_ARRAY_LENGTH_OFFSET;

	private static final ThreadLocal<Object[]> THREADLOCAL_OBJECT_ARRAY = new ThreadLocal<Object[]>() {
		protected Object[] initialValue() {
			return new Object[1];
		}
	};

	private static Object[] getThreadLocalObjectArray() {
		return THREADLOCAL_OBJECT_ARRAY.get();
	}

	static {
		try {
			ByteBuffer buffer = ByteBuffer.allocateDirect(1);
			Field unsafeField = buffer.getClass().getDeclaredField("unsafe");
			unsafeField.setAccessible(true);
			unsafe = (Unsafe) unsafeField.get(buffer);

			addressOffset = getObjectFieldOffset(buffer, "address");
			positionOffset = getObjectFieldOffset(buffer, "position");
			limitOffset = getObjectFieldOffset(buffer, "limit");
			capacityOffset = getObjectFieldOffset(buffer, "capacity");

			buffer.flip();
			buffer = null;
		} catch (Exception exc) {
			exc.printStackTrace();
			throw new InternalError();
		}

		WORD_SIZE_BITS = unsafe.addressSize() * 8;
		if (WORD_SIZE_BITS != 32 && WORD_SIZE_BITS != 64)
			throw new IllegalStateException("WORD_SIZE: " + WORD_SIZE_BITS);
		OBJECT_HEADER_SIZE = WORD_SIZE_BITS / 8 * 2;

		BYTE_ARRAY_BASE_OFFSET = unsafe.arrayBaseOffset(new byte[4].getClass());
		SHORT_ARRAY_BASE_OFFSET = unsafe.arrayBaseOffset(new short[4].getClass());
		INT_ARRAY_BASE_OFFSET = unsafe.arrayBaseOffset(new int[4].getClass());
		LONG_ARRAY_BASE_OFFSET = unsafe.arrayBaseOffset(new long[4].getClass());
		FLOAT_ARRAY_BASE_OFFSET = unsafe.arrayBaseOffset(new float[4].getClass());
		DOUBLE_ARRAY_BASE_OFFSET = unsafe.arrayBaseOffset(new double[4].getClass());
		OBJECT_ARRAY_BASE_OFFSET = unsafe.arrayBaseOffset(new Object[4].getClass());

		BYTE_ARRAY_LENGTH_OFFSET = getArrayLengthOffset(byte.class);
		SHORT_ARRAY_LENGTH_OFFSET = getArrayLengthOffset(short.class);
		INT_ARRAY_LENGTH_OFFSET = getArrayLengthOffset(int.class);
		LONG_ARRAY_LENGTH_OFFSET = getArrayLengthOffset(long.class);
		FLOAT_ARRAY_LENGTH_OFFSET = getArrayLengthOffset(float.class);
		DOUBLE_ARRAY_LENGTH_OFFSET = getArrayLengthOffset(double.class);
		OBJECT_ARRAY_LENGTH_OFFSET = getArrayLengthOffset(Object.class);
	}

	private static int getArrayLengthOffset(Class<?> prim) {
		final int len = 1337;
		Object array = Array.newInstance(prim, len);
		long pntr = getObjectAddress(array);
		// in 64bit the array.length field is part of the object header
		for (int i = 0; i < OBJECT_HEADER_SIZE * 2; i += 4) {
			if (unsafe.getInt(pntr + i) == len) {
				return i;
			}
		}
		throw new InternalError();
	}

	public static void memcpy(long p1, long p2, long count) {
		unsafe.copyMemory(p1, p2, count);
	}

	public static void unmap(final MappedByteBuffer buffer) {
		/**
		 * let's crash the jvm!
		 */
		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run() {
				try {
					Method getCleanerMethod = buffer.getClass().getMethod("cleaner", new Class[0]);
					getCleanerMethod.setAccessible(true);
					sun.misc.Cleaner cleaner = (sun.misc.Cleaner) getCleanerMethod.invoke(buffer, new Object[0]);
					cleaner.clean();
				} catch (Exception e) {
					e.printStackTrace();
				}
				return null;
			}
		});
	}

	public static final long getFieldOffset(Field field) {
		return unsafe.objectFieldOffset(field);
	}

	public static final long getFieldOffset(Class<?> clazz, String name) {
		return unsafe.objectFieldOffset(getFieldByName(clazz, name));
	}

	public static final long getObjectFieldOffset(Object obj, String name) {
		return getFieldOffset(obj.getClass(), name);
	}

	public static final long getObjectAddress(Object obj) {
		Object[] arr = getThreadLocalObjectArray();
		arr[0] = obj;

		if (WORD_SIZE_BITS == 32)
			return unsafe.getInt(arr, OBJECT_ARRAY_BASE_OFFSET);
		if (WORD_SIZE_BITS == 64)
			return unsafe.getLong(arr, OBJECT_ARRAY_BASE_OFFSET);

		throw new IllegalStateException();
	}

	public static final Object getObjectAtAddress(long addr) {
		Object[] arr = getThreadLocalObjectArray();

		if (WORD_SIZE_BITS == 32)
			unsafe.putInt(arr, OBJECT_ARRAY_BASE_OFFSET, (int) (addr & 0xFFFFFFFF));
		if (WORD_SIZE_BITS == 64)
			unsafe.putLong(arr, OBJECT_ARRAY_BASE_OFFSET, addr);

		return arr[0];
	}

	public static final Pair<float[], FloatBuffer> createSharedFloatData(int length) {
		long pntr = unsafe.allocateMemory((long) (length << 2) + OBJECT_HEADER_SIZE);
		float[] array = createFloatArrayAt(pntr, length);
		FloatBuffer buffer = createFloatBufferAt(pntr + OBJECT_HEADER_SIZE, length);
		return new Pair<float[], FloatBuffer>(array, buffer);
	}

	public static final float[] createFloatArrayAt(long pntr, int len) {
		copyObjectHeaderTo(new float[0], pntr);

		// write length
		unsafe.putInt(pntr + FLOAT_ARRAY_LENGTH_OFFSET, len);

		float[] arr = (float[]) NativeHacks.fakePointerAsObject(pntr);
		assert arr.length == len;
		return arr;
	}

	public static final FloatBuffer createFloatBufferAt(long pntr, int len) {
		Native.zeroOut(pntr, len << 2);

		FloatBuffer buf = ByteBuffer.allocateDirect(4).order(ByteOrder.nativeOrder()).asFloatBuffer();
		setBufferProperties(buf, pntr, 0, len, len);
		buf.clear();

		return buf;
	}

	public static final Object fakePointerAsObject(long addr) {
		Object[] arr = getThreadLocalObjectArray();

		if (WORD_SIZE_BITS == 32)
			unsafe.putInt(arr, OBJECT_ARRAY_BASE_OFFSET, (int) (addr & 0xFFFFFFFF));
		else if (WORD_SIZE_BITS == 64)
			unsafe.putLong(arr, OBJECT_ARRAY_BASE_OFFSET, addr);
		else
			throw new IllegalStateException();

		return arr[0];
	}

	public static final void copyObjectHeaderTo(Object obj, long pntr) {
		for (int i = 0; i < OBJECT_HEADER_SIZE; i++)
			unsafe.putByte(pntr + i, unsafe.getByte(obj, (long) i));
	}

	public static final long getBufferAddress(Buffer bb) {
		if (!bb.isDirect()) {
			throw new IllegalStateException();
		}
		return unsafe.getLong(bb, addressOffset);
	}

	public static final void setBufferAddress(Buffer bb, long address) {
		unsafe.putLong(bb, addressOffset, address);
	}

	public static final void setBufferProperties(Buffer bb, long address, int capacity) {
		setBufferProperties(bb, address, 0, capacity, capacity);
	}

	public static final void setBufferProperties(Buffer bb, long address, int position, int limit, int capacity) {
		if (address != -1L)
			unsafe.putLong(bb, addressOffset, address);
		if (position != -1)
			unsafe.putInt(bb, positionOffset, position);
		if (limit != -1)
			unsafe.putInt(bb, limitOffset, limit);
		if (capacity != -1)
			unsafe.putInt(bb, capacityOffset, capacity);
	}

	private static final Field getFieldByName(Class<?> clazz, String name) {
		Class<?> clzz = clazz;

		do {
			try {
				return clazz.getDeclaredField(name);
			} catch (Exception exc) {
				clazz = clazz.getSuperclass();
			}
		} while (clazz != null);

		throw new IllegalArgumentException("No Field named \"" + name + "\" found in " + clzz.getName());
	}

	public static final Unsafe instance() {
		return unsafe;
	}
}
