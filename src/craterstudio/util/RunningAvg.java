package craterstudio.util;

public class RunningAvg {
	private final long[] values;
	private int counter;

	public RunningAvg(int slots) {
		values = new long[slots];
	}

	public void add(long value) {
		values[counter++ % values.length] = value;
	}

	public int size() {
		return Math.min(counter, values.length);
	}

	public int addCount() {
		return counter;
	}

	public long avg() {
		int samples = this.size();
		if (samples == 0)
			throw new IllegalStateException();
		long sum = 0;
		for (int i = 0; i < samples; i++) {
			sum += values[i];
		}
		return sum / samples;
	}

	public long min() {
		int samples = this.size();
		if (samples == 0)
			throw new IllegalStateException();
		long min = Long.MAX_VALUE;
		for (int i = 0; i < samples; i++) {
			min = Math.min(min, values[i]);
		}
		return min;
	}

	public long max() {
		int samples = this.size();
		if (samples == 0)
			throw new IllegalStateException();
		long max = Long.MIN_VALUE;
		for (int i = 0; i < samples; i++) {
			max = Math.max(max, values[i]);
		}
		return max;
	}
}
