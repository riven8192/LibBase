/*
 * Created on 31 okt 2008
 */

package craterstudio.data.tuples;

import java.io.Serializable;

public class Triple<T> implements Serializable
{
   private final T a;
   private final T b;
   private final T c;

   public Triple(T a, T b, T c)
   {
      this.a = a;
      this.b = b;
      this.c = c;
   }

   public T first()
   {
      return this.a;
   }

   public T second()
   {
      return this.b;
   }

   public T third()
   {
      return this.c;
   }

   @Override
   public int hashCode()
   {
      int ah = a == null ? 0 : a.hashCode();
      int bh = b == null ? 0 : b.hashCode();
      int ch = c == null ? 0 : c.hashCode();
      return ah ^ (bh * 37) ^ (ch * 13);
   }

   @Override
   public boolean equals(Object obj)
   {
      if (!(obj instanceof Triple< ? >))
         return false;

      Triple< ? > that = (Triple< ? >) obj;
      return eq(this.a, that.a) && eq(this.b, that.b) && eq(this.c, that.c);
   }

   private static final boolean eq(Object a, Object b)
   {
      if (a == b)
         return true;
      if (a == null ^ b == null)
         return false;

      if (a != null)
         return a.equals(b);
      if (b != null)
         return b.equals(a);

      return false;
   }

   @Override
   public String toString()
   {
      return "Triple[" + this.a + ", " + this.b + ", " + this.c + "]";
   }
}
