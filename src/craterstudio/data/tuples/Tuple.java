/*
 * Created on 31 okt 2008
 */

package craterstudio.data.tuples;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Tuple<T> implements Serializable
{
   private final List<T> vals;

   public Tuple(List<T> vals)
   {
      this.vals = vals;
   }

   public Tuple(T... vals)
   {
      this.vals = new ArrayList<T>();
      for (T val : vals)
         this.vals.add(val);
   }

   public T get(int index)
   {
      return this.vals.get(index);
   }

   public int values()
   {
      return vals.size();
   }

   @Override
   public int hashCode()
   {
      int h = 0;
      for (T t : this.vals)
      {
         h ^= (t == null) ? 0 : t.hashCode();
         h *= 37;
      }
      return h;
   }

   @Override
   public boolean equals(Object obj)
   {
      if (!(obj instanceof Tuple< ? >))
         return false;

      Tuple< ? > that = (Tuple< ? >) obj;
      if (this.vals.size() != that.vals.size())
         return false;

      for (int i = 0; i < this.vals.size(); i++)
         if (!eq(this.vals.get(i), that.vals.get(i)))
            return false;
      return true;
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
