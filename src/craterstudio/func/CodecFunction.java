/*
 * Created on 4 mrt 2011
 */

package craterstudio.func;

public class CodecFunction
{
   public static <A, B> Function<A> create(final Codec<A, B> codec, final Function<B> func)
   {
      return new Function<A>()
      {
         @Override
         public A operate(A item)
         {
            return codec.decode(func.operate(codec.encode(item)));
         }
      };
   }

}
