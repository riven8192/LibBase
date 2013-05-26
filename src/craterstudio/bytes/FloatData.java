package craterstudio.bytes;

import java.nio.ByteOrder;
import java.nio.FloatBuffer;

public class FloatData {
	public final FloatBuffer fb;
	public final long base, max;
	public long pntr;

	public FloatData(FloatBuffer fb) {
		if (fb == null || !fb.isDirect() || fb.order() != ByteOrder.nativeOrder())
			throw new IllegalArgumentException();

		this.fb = fb;
		base = pntr = NativeHacks.getBufferAddress(fb);
		max = base + ((fb.capacity() - 1) << 2);
	}

	public void reset() {
		pntr = base;
	}

	public int bytes() {
		return (int) (pntr - base);
	}

	public int values() {
		return (int) ((pntr - base) >> 2);
	}

	public long capacity() {
		return fb.capacity();
	}

	public void checkRange() {
		assert (pntr >= base);
		assert (pntr <= max);
	}

	public void checkRange(int floatCount) {
		assert (pntr + (floatCount << 2) >= base);
		assert (pntr + (floatCount << 2) <= max);
	}

	public void advance(int floatCount) {
		pntr += (floatCount << 2);
	}

	public void put(int index, float val) {
		Native.fput(pntr + (index << 2), val);
	}

	public FloatBuffer sync() {
		fb.position(0);
		fb.limit(this.values());
		return fb;
	}
}
