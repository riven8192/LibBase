/*
 * Created on 29 jun 2010
 */

package craterstudio.func;

public interface TryProducer<T, E extends Exception>
{
   public static final Object NO_RESULT = new Object();

   public T produce() throws E;
}
