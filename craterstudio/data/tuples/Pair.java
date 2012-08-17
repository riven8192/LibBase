/*
 * Created on 31 okt 2008
 */

package craterstudio.data.tuples;

import java.io.Serializable;

public class Pair<A, B> implements Serializable
{
   private final A a;
   private final B b;

   public Pair(A a, B b)
   {
      this.a = a;
      this.b = b;
   }

   public A first()
   {
      return this.a;
   }

   public B second()
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
      return "Pair[" + this.a + ", " + this.b + "]";
   }

   @Override
   public boolean equals(Object obj)
   {
      if (!(obj instanceof Pair< ? , ? >))
         return false;

      Pair< ? , ? > that = (Pair< ? , ? >) obj;
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
