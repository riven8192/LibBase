/*
 * Created on 23 jun 2011
 */

package craterstudio.func;

public interface ObjectStream<T>
{
   public static final Object END_OF_STREAM = new Object();

   public T next();

   public void remove();
}
