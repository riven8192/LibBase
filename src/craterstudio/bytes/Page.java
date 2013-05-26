/*
 * Created on 19-sep-2007
 */

package craterstudio.bytes;

class Page {
	private final long pntr;

	public Page(long pntr) {
		if (pntr % NativeAllocator.pageSize() != 0) {
			throw new IllegalArgumentException("pointer not on page boundary");
		}
		this.pntr = pntr;
	}

	public final long pntr() {
		return pntr;
	}

	public final void clear() {
		Native.fillOut(this.pntr(), NativeAllocator.pageSize(), (byte) 0x00);
	}

	public static final int countFits(int bytes) {
		return NativeAllocator.pageSize() / bytes;
	}

	public static final void copy(Page src, Page dst) {
		Native.copyPages(src.pntr(), dst.pntr(), 1);
	}
}