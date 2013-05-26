/*
 * Created on 12 feb 2010
 */

package craterstudio.text;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import craterstudio.data.LRUMap;
import craterstudio.data.tuples.Pair;

public class RegexpCache<T>
{
   private final List<Pair<Pattern, T>> patternAndItem;
   private final LRUMap<String, T>      matchToItem;

   public RegexpCache(int poolSize)
   {
      this.patternAndItem = new ArrayList<Pair<Pattern, T>>();
      this.matchToItem = new LRUMap<String, T>(poolSize, false);
   }

   public void clear()
   {
      this.patternAndItem.clear();

      this.matchToItem.clear();
   }

   public void addPattern(String regexp, T item)
   {
      Pattern pattern = Pattern.compile(regexp);

      this.patternAndItem.add(new Pair<Pattern, T>(pattern, item));

      this.matchToItem.clear();
   }

   public T getItem(String value)
   {
      if (this.matchToItem.contains(value))
      {
         // service can be null!
         return this.matchToItem.get(value);
      }

      T item = null;

      // find item of (rewritten) value
      for (Pair<Pattern, T> pair : this.patternAndItem)
      {
         if (pair.first().matcher(value).matches())
         {
            item = pair.second();
            break;
         }
      }

      // service can be null!
      this.matchToItem.put(value, item);

      return item;
   }
}
