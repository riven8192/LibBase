/*
 * Created on 8 dec 2008
 */

package craterstudio.data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.Map.Entry;

public class Histogram<T>
{
   private final Map<T, Integer> map;

   public Histogram()
   {
      this.map = new HashMap<T, Integer>();
   }

   public void clear()
   {
      this.map.clear();
   }

   public int put(T t)
   {
      return this.put(t, 1);
   }

   public int put(T t, int amount)
   {
      if (amount < 0)
         throw new IllegalArgumentException();

      int count = this.get(t);
      if (amount == 0)
         return count;

      count += amount;
      this.map.put(t, Integer.valueOf(count));
      return count;
   }

   public int get(T t)
   {
      Integer count = this.map.get(t);
      if (count == null)
         return 0;
      return count.intValue();
   }

   public List<T> thresholdKeys(int minValue)
   {
      int amount = 0;
      for (Entry<T, Integer> e : this.map.entrySet())
         if (e.getValue().intValue() >= minValue)
            amount++;
      return topKeys(amount);

   }

   public List<T> topKeys()
   {
      return this.topKeys(Integer.MAX_VALUE);
   }

   public List<T> topKeys(int amount)
   {
      List<T> kList = new ArrayList<T>();
      List<Integer> vList = new ArrayList<Integer>();

      for (Entry<T, Integer> e : this.map.entrySet())
      {
         if (vList.size() == amount + 1)
         {
            // when overflowed, remove lowest
            int index = indexOfMin(vList);
            kList.remove(index);
            vList.remove(index);
         }

         kList.add(e.getKey());
         vList.add(e.getValue());
      }

      // bubble sort, assuming 'amount' is reasonably small
      for (int i = 0; i < vList.size(); i++)
      {
         for (int k = i + 1; k < vList.size(); k++)
         {
            if (vList.get(i).intValue() >= vList.get(k).intValue())
            {
               continue;
            }

            Integer a = vList.get(i);
            Integer b = vList.get(k);
            vList.set(k, a);
            vList.set(i, b);

            T x = kList.get(i);
            T y = kList.get(k);
            kList.set(k, x);
            kList.set(i, y);
         }
      }

      if (kList.size() == amount + 1)
      {
         // drop smallest item, if overflowed
         kList.remove(kList.size() - 1);
         vList.remove(vList.size() - 1);
      }

      return kList;
   }

   public int remove(T t)
   {
      return this.remove(t, 1);
   }

   public int remove(T t, int amount)
   {
      Integer count = this.map.get(t);
      if (count == null)
         throw new NoSuchElementException(String.valueOf(t));
      if (amount < 0)
         throw new IllegalArgumentException();
      if (count.intValue() < amount)
         throw new IllegalStateException("cannot remove");

      count = Integer.valueOf(count.intValue() - amount);
      if (count.intValue() == 0)
         this.map.remove(t);
      else
         this.map.put(t, count);

      return count.intValue();
   }

   public int reset(T t)
   {
      Integer count = this.map.remove(t);
      if (count == null)
         return 0;
      return count.intValue();
   }

   public int set(T t, int val)
   {
      if (val < 0)
         throw new IllegalArgumentException();
      Integer count = this.map.get(t);

      if (count == null)
      {
         if (val != 0)
            this.map.put(t, Integer.valueOf(val));
         return 0;
      }

      if (val == 0)
         return this.map.remove(t).intValue();
      return this.map.put(t, Integer.valueOf(val)).intValue();
   }

   public Set<T> keys()
   {
      return this.map.keySet();
   }

   private static int indexOfMin(List<Integer> ids)
   {
      int minAt = 0;
      for (int i = 1; i < ids.size(); i++)
         if (ids.get(i).intValue() < ids.get(minAt).intValue())
            minAt = i;
      return minAt;
   }

   //

   public Histogram<T> asSynchronized()
   {
      return new Histogram<T>()
      {
         public synchronized int put(T t)
         {
            return super.put(t);
         }

         public synchronized int put(T t, int amount)
         {
            return super.put(t, amount);
         }

         public synchronized int get(T t)
         {
            return super.get(t);
         }

         public synchronized int remove(T t)
         {
            return super.remove(t);
         }

         public synchronized int reset(T t)
         {
            return super.reset(t);
         }

         public synchronized int set(T t, int val)
         {
            return super.set(t, val);
         }

         @Override
         public synchronized Set<T> keys()
         {
            return super.keys();
         }

         @Override
         public synchronized List<T> topKeys()
         {
            return super.topKeys();
         }

         @Override
         public synchronized List<T> topKeys(int amount)
         {
            return super.topKeys(amount);
         }

         @Override
         public boolean equals(Object obj)
         {
            return super.equals(obj);
         }

         @Override
         public int hashCode()
         {
            return super.hashCode();
         }

         @Override
         public String toString()
         {
            return super.toString();
         }

         @Override
         public Histogram<T> asSynchronized()
         {
            return this;
         }
      };
   }
}
