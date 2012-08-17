/*
 * Created on 15 jun 2010
 */

package craterstudio.func;

public interface Exctractor<I, O>
{
   public Iterable<O> extract(I input);
}
