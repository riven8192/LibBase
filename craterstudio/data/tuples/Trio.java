/*
 * Created on 31 okt 2008
 */

package craterstudio.data.tuples;

import java.io.Serializable;

public class Trio<A, B, C> implements Serializable
{
   private final A a;
   private final B b;
   private final C c;

   public Trio(A a, B b, C c)
   {
      this.a = a;
      this.b = b;
      this.c = c;
   }

   public A first()
   {
      return this.a;
   }

   public B second()
   {
      return this.b;
   }

   public C third()
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
      if (!(obj instanceof Trio< ? , ? , ? >))
         return false;

      Trio< ? , ? , ? > that = (Trio< ? , ? , ? >) obj;
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
      return "Trio[" + this.a + ", " + this.b + ", " + this.c + "]";
   }
}
