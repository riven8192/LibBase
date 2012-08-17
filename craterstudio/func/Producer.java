/*
 * Created on 29 jun 2010
 */

package craterstudio.func;

public interface Producer<T>
{
   public static final Object NO_RESULT = new Object();
   
   public T produce();
}
