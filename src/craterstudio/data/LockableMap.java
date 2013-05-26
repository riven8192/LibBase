package craterstudio.data;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class LockableMap extends HashMap<String, String> {
	private final AtomicBoolean isLocked = new AtomicBoolean(false);

	public void lock() {
		isLocked.set(true);
	}

	public boolean isLocked() {
		return isLocked.get();
	}

	private void checkLocked() {
		if (isLocked.get()) {
			throw new IllegalStateException("locked");
		}
	}

	@Override
	public void clear() {
		this.checkLocked();
		super.clear();
	}

	@Override
	public String put(String key, String value) {
		this.checkLocked();
		return super.put(key, value);
	}

	@Override
	public void putAll(Map<? extends String, ? extends String> m) {
		this.checkLocked();
		super.putAll(m);
	}

	@Override
	public String remove(Object key) {
		this.checkLocked();
		return super.remove(key);
	}
}