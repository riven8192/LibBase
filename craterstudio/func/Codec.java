/*
 * Created on 15 jun 2010
 */

package craterstudio.func;

public interface Codec<A, B>
{
   public B encode(A value);

   public A decode(B encoded);
}