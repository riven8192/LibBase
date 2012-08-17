/*
 * Created on 15 jun 2010
 */

package craterstudio.func;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class DataSet<T>
{
   private List<T> items;

   public DataSet()
   {
      this.items = new ArrayList<T>();
   }

   public DataSet(Collection<T> collection)
   {
      this();

      this.items.addAll(collection);
   }

   public <O> DataSet<O> extract(Exctractor<T, O> func)
   {
      DataSet<O> result = new DataSet<O>();
      for (T item : this.items)
         for (O output : func.extract(item))
            result.items.add(output);
      return result;
   }

   public DataSet<T> filter(Filter<T> func)
   {
      DataSet<T> result = new DataSet<T>();
      for (T item : this.items)
         if (func.accept(item))
            result.items.add(item);
      return result;
   }

   public DataSet<T> apply(Function<T> func)
   {
      DataSet<T> result = new DataSet<T>();
      for (T item : this.items)
         result.items.add(func.operate(item));
      return result;
   }
}