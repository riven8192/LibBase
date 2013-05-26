/*
 * Created on 15 jun 2010
 */

package craterstudio.func;

public interface Transformer<I, O>
{
   public O transform(I value);
}