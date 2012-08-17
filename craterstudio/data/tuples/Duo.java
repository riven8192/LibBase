/*
 * Created on 31 okt 2008
 */

package craterstudio.data.tuples;

import java.io.Serializable;

public class Duo<T> implements Serializable
{
   private final T a;
   private final T b;

   public Duo(T a, T b)
   {
      this.a = a;
      this.b = b;
   }

   public T first()
   {
      return this.a;
   }

   public T second()
   {
      return this.b;
   }

   @Override
   public int hashCode()
   {
      int ah = a == null ? 0 : a.hashCode();
      int bh = b == null ? 0 : b.hashCode();
      return ah ^ (bh * 37);
   }

   @Override
   public String toString()
   {
      return "Duo[" + this.a + ", " + this.b + "]";
   }

   @Override
   public boolean equals(Object obj)
   {
      if (!(obj instanceof Duo< ? >))
         return false;

      Duo<T> that = (Duo<T>) obj;
      return eq(this.a, that.a) && eq(this.b, that.b);
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
}
