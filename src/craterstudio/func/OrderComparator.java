/*
 * Created on 28 sep 2010
 */

package craterstudio.func;

import java.util.Comparator;

public abstract class OrderComparator<T> implements Comparator<T>
{
   public abstract boolean areEqual(T o1, T o2);

   public abstract boolean isOrdered(T o1, T o2);

   @Override
   public final int compare(T o1, T o2)
   {
      return this.areEqual(o1, o2) ? 0 : this.isOrdered(o1, o2) ? -1 : +1;
   }

   public OrderComparator<T> reversed()
   {
      return new OrderComparator<T>()
      {
         public boolean areEqual(T o1, T o2)
         {
            return OrderComparator.this.areEqual(o2, o1);
         }

         @Override
         public boolean isOrdered(T o1, T o2)
         {
            return OrderComparator.this.isOrdered(o2, o1);
         }
      };
   }
}
