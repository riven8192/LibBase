/*
 * Created on 31 okt 2008
 */

package craterstudio.data.tuples;

import java.io.Serializable;

public class IntPair implements Serializable
{
   private final int a;
   private final int b;

   public IntPair(int a, int b)
   {
      this.a = a;
      this.b = b;
   }

   public int a()
   {
      return this.a;
   }

   public int b()
   {
      return this.b;
   }

   @Override
   public int hashCode()
   {
      return a ^ (b * 37);
   }

   @Override
   public boolean equals(Object obj)
   {
      if (!(obj instanceof IntPair))
         return false;

      IntPair that = (IntPair) obj;
      return (this.a == that.a) && (this.b == that.b);
   }
}
