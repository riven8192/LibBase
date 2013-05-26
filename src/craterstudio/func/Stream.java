package craterstudio.func;

public interface Stream<T> {
	public boolean reachedEnd();

	public T poll();
}
