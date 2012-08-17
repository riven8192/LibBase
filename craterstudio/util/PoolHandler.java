/*
 * Created on Aug 7, 2005
 */
package craterstudio.util;

public interface PoolHandler<T>
{
   public T create();

   public void clean(T t);
}
