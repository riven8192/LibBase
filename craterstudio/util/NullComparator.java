/*
 * Created on 11 mei 2011
 */

package craterstudio.util;

import java.util.Comparator;

public class NullComparator<T> implements Comparator<T>
{
   private final Comparator<T> backing;

   public NullComparator(Comparator<T> backing)
   {
      this.backing = backing;
   }

   public int compare(T a, T b)
   {
      if (a == b)
         return 0;
      if (a == null)
         return -1;
      if (b == null)
         return +1;
      return this.backing.compare(a, b);
   }
}
