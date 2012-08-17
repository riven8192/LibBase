/*
 * Created on 31 okt 2008
 */

package craterstudio.data.tuples;

import java.io.Serializable;

public class Quad<A, B, C, D> implements Serializable
{
   private final A a;
   private final B b;
   private final C c;
   private final D d;

   public Quad(A a, B b, C c, D d)
   {
      this.a = a;
      this.b = b;
      this.c = c;
      this.d = d;
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

   public D fourth()
   {
      return this.d;
   }

   @Override
   public int hashCode()
   {
      int ah = a == null ? 0 : a.hashCode();
      int bh = b == null ? 0 : b.hashCode();
      int ch = c == null ? 0 : c.hashCode();
      int dh = d == null ? 0 : d.hashCode();
      return ah ^ (bh * 37) ^ (ch * 13) ^ (dh * 53);
   }

   @Override
   public boolean equals(Object obj)
   {
      if (!(obj instanceof Quad< ? , ? , ? , ? >))
         return false;

      Quad< ? , ? , ? , ? > that = (Quad< ? , ? , ? , ? >) obj;
      return eq(this.a, that.a) && eq(this.b, that.b) && eq(this.c, that.c) && eq(this.d, that.d);
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
      return "Quad[" + this.a + ", " + this.b + ", " + this.c + ", " + this.d + "]";
   }
}
