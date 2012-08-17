/*
 * Created on 31 okt 2008
 */

package craterstudio.data.tuples;

import java.io.Serializable;

public class LongPair implements Serializable
{
   private final long a;
   private final long b;

   public LongPair(long a, long b)
   {
      this.a = a;
      this.b = b;
   }

   public long a()
   {
      return this.a;
   }

   public long b()
   {
      return this.b;
   }

   @Override
   public int hashCode()
   {
      return (int) (a ^ (b * 37));
   }

   @Override
   public boolean equals(Object obj)
   {
      if (!(obj instanceof LongPair))
         return false;

      LongPair that = (LongPair) obj;
      return (this.a == that.a) && (this.b == that.b);
   }
}
