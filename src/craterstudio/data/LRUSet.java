/*
 * Created on 15 okt 2009
 */

package craterstudio.data;

public interface LRUSet<T> extends Iterable<T>
{
   public int size();

   public int capacity();

   public T put(T elem);

   public boolean contains(T elem);

   public boolean remove(T elem);

   public void clear();
}