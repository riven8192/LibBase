/*
 * Created on 15-mei-2005
 */
package craterstudio.util;

public class BucketArraySorter
{
   private final int       min, max, buckets;

   private Bag<Sortable>   less  = new Bag<Sortable>();
   private Bag<Sortable>[] parts = new Bag[0];
   private Bag<Sortable>   more  = new Bag<Sortable>();
   private Sortable[]      aux   = new Sortable[64];

   public BucketArraySorter(int min, int max, int buckets)
   {
      this.min = min;
      this.max = max;
      this.buckets = buckets;
   }

   public void sort(Sortable[] p, int off, int len)
   {
      for (int i = 0; i < len; i++)
         p[off + i].calcSortIndex();

      this.sortImpl(p, off, len, this.min, this.max, this.buckets);
   }

   private final void sortImpl(Sortable[] p, int off, int len, int min, int max, int buckets)
   {
      if (parts.length < buckets)
      {
         parts = new Bag[buckets];

         for (int i = 0; i < parts.length; i++)
            parts[i] = new Bag<Sortable>();
      }

      // distribute sortables over bags
      for (int i = 0; i < len; i++)
      {
         Sortable s = p[off + i];
         int index = s.getSortIndex();

         if (index < min)
            less.put(s);
         else if (index >= max)
            more.put(s);
         else
         {
            float percent = (float) (s.getSortIndex() - min) / (max - min);
            int arrayIndex = (int) (percent * buckets);
            parts[arrayIndex].put(s);
         }
      }

      // sort lists, overwrite P

      int size;

      // fetch and sort all the values less than MIN
      if ((size = less.size()) != 0)
      {
         this.fetchSortStoreClear(p, off, less);
         off += size;
      }

      for (int i = 0; i < buckets; i++)
      {
         if ((size = parts[i].size()) != 0)
         {
            this.fetchSortStoreClear(p, off, parts[i]);
            off += size;
         }
      }

      // fetch and sort all the values more than MAX
      if ((size = more.size()) != 0)
      {
         this.fetchSortStoreClear(p, off, more);
         off += size;
      }
   }

   private final void fetchSortStoreClear(Sortable[] p, int off, Bag<Sortable> bag)
   {
      // fetch
      aux = ArrayUtil.ensure(aux, bag.size());
      bag.fillArray(aux);

      // sort
      ArraySorter.sortImpl(aux, 0, bag.size());

      // store
      System.arraycopy(aux, 0, p, off, bag.size());

      // clear
      bag.clear();
   }
}