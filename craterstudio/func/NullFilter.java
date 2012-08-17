/*
 * Created on 15 jun 2010
 */

package craterstudio.func;

public class NullFilter<T> implements Filter<T>
{
   public boolean accept(T value)
   {
      return (value != null);
   }
}