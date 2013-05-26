package craterstudio.func;

import java.util.NoSuchElementException;

public interface DataSource<T> {
	public T produce() throws NoSuchElementException;
}
