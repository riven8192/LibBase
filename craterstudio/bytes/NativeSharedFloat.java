/*
 * Created on 12 mei 2009
 */

package craterstudio.bytes;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.nio.FloatBuffer;
import java.util.Arrays;

public class NativeSharedFloat {
	public static void main(String[] args) {

		ThreadGroup group = Thread.currentThread().getThreadGroup();
		while (group.getParent() != null)
			group = group.getParent();

		Thread[] ts = new Thread[100];
		int count = group.enumerate(ts);
		for (int i = 0; i < count; i++) {
			System.out.println(ts[i]);

			if (ts[i].getName().equals("Reference Handler")) {
				System.out.println("boo");
				ts[i].suspend();
			}
			if (ts[i].getName().equals("Finalizer")) {
				System.out.println("boo");
				ts[i].suspend();
			}
			if (ts[i].getName().equals("Signal Dispatcher")) {
				System.out.println("boo");
				ts[i].suspend();
			}
			if (ts[i].getName().equals("Attach Listener")) {
				System.out.println("boo");
				ts[i].suspend();
			}
		}

		//

		int len = 1024;
		long baseOffset = NativeHacks.FLOAT_ARRAY_BASE_OFFSET;
		long pntr = NativeAllocator.malloc(baseOffset + len * 4);

		float[] arr = NativeHacks.createFloatArrayAt(pntr, len);
		FloatBuffer buf = NativeHacks.createFloatBufferAt(pntr + baseOffset, len);

		System.out.println("arr.length=" + arr.length);
		System.out.println("buf.capacity=" + buf.capacity());

		System.out.println();
		System.out.println("arr[0] = " + arr[0]);
		System.out.println("buf(0) = " + buf.get(0));

		arr[0] = 12.34f;

		System.out.println();
		System.out.println("arr[0] = " + arr[0]);
		System.out.println("buf(0) = " + buf.get(0));

		checkSharedPointers(arr, buf);
		System.out.println("garbageCollectionCount=" + garbageCollectionCount());

		createGarbageAndCleanup();

		checkSharedPointers(arr, buf);
		System.out.println("garbageCollectionCount=" + garbageCollectionCount());

		arr[0] = 23.45f;

		System.out.println();
		System.out.println("arr[0] = " + arr[0]);
		System.out.println("buf(0) = " + buf.get(0));
	}

	private static int garbageCollectionCount() {
		int sum = 0;
		for (GarbageCollectorMXBean bean : ManagementFactory.getGarbageCollectorMXBeans()) {
			sum += bean.getCollectionCount();
		}
		return sum;
	}

	private static void checkSharedPointers(float[] arr, FloatBuffer fb) {
		long pArr = NativeHacks.getObjectAddress(arr) + NativeHacks.FLOAT_ARRAY_BASE_OFFSET;
		long pBuf = NativeHacks.getBufferAddress(fb);

		if (pArr != pBuf)
			throw new IllegalStateException();

		System.out.println("pArr=" + pArr);
		System.out.println("pBuf=" + pBuf);
	}

	private static void createGarbageAndCleanup() {
		final int dim = 256;

		String[] arr = new String[dim * dim];

		for (int i = 0; i < dim; i++) {
			for (int k = 0; k < dim; k++) {
				arr[i * dim + k] = String.valueOf(i) + String.valueOf(k);
			}
		}

		// ensure 'arr' cannot be optimized away
		int h = Arrays.hashCode(arr) % 2;

		long usedBefore = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
		for (int i = 0; i < (8 + h); i++) {
			System.gc();
		}
		long usedAfter = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
		System.out.println("collected garbage: " + (usedBefore - usedAfter) / 1024 + "KB");
	}
}
