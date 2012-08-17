/*
 * Created on Aug 15, 2008
 */

package craterstudio.util;

import java.util.AbstractCollection;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

public class ArrayMap<K, V> implements Map<K, V>
{
   K[] keys;
   V[] vals;
   int size;

   public ArrayMap()
   {
      keys = (K[]) new Object[4];
      vals = (V[]) new Object[4];
   }

   public void prioritize(K k)
   {
      int i = this.indexOfKey(k);
      if (i == -1)
         throw new NoSuchElementException();
      if (i == 0)
         return;
      ArrayUtil.swap(this.keys, 0, i);
      ArrayUtil.swap(this.vals, 0, i);
   }

   @Override
   public void clear()
   {
      for (int i = 0; i < size; i++)
      {
         keys[i] = null;
         vals[i] = null;
      }

      size = 0;
   }

   @Override
   public boolean containsKey(Object k)
   {
      return this.indexOfKey((K) k) != -1;
   }

   @Override
   public boolean containsValue(Object v)
   {
      for (int i = 0; i < size; i++)
         if (eq(vals[i], v))
            return true;
      return false;
   }

   @Override
   public boolean isEmpty()
   {
      return size == 0;
   }

   @Override
   public int size()
   {
      return size;
   }

   @Override
   public void putAll(Map< ? extends K, ? extends V> m)
   {
      for (Entry< ? extends K, ? extends V> e : m.entrySet())
         this.put(e.getKey(), e.getValue());
   }

   public V put(K k, V v)
   {
      int i = this.indexOfKey(k);

      if (i != -1)
      {
         V curr = vals[i];
         vals[i] = v;
         return curr;
      }

      if (size == keys.length)
      {
         keys = ArrayUtil.growBy(keys, size);
         vals = ArrayUtil.growBy(vals, size);
      }

      keys[size] = k;
      vals[size] = v;
      size++;
      return null;
   }

   @Override
   public V get(Object k)
   {
      int i = this.indexOfKey((K) k);
      if (i == -1)
         return null;
      return vals[i];
   }

   @Override
   public V remove(Object k)
   {
      int i = this.indexOfKey((K) k);
      if (i == -1)
         return null;

      V curr = vals[i];

      int newSize = size - 1;
      if (i != newSize)
      {
         ArrayUtil.swap(this.keys, i, newSize, this.size);
         ArrayUtil.swap(this.vals, i, newSize, this.size);

         keys[newSize] = null;
         vals[newSize] = null;
      }

      size = newSize;

      return curr;
   }

   @Override
   public Set<K> keySet()
   {
      return new AbstractSet<K>()
      {
         @Override
         public Iterator<K> iterator()
         {
            return IteratorUtil.iterator(ArrayMap.this.keys, 0, ArrayMap.this.size);
         }

         @Override
         public int size()
         {
            return ArrayMap.this.size;
         }
      };
   }

   @Override
   public Collection<V> values()
   {
      return new AbstractCollection<V>()
      {
         @Override
         public Iterator<V> iterator()
         {
            return IteratorUtil.iterator(ArrayMap.this.vals, 0, ArrayMap.this.size);
         }

         @Override
         public int size()
         {
            return ArrayMap.this.size;
         }
      };
   }

   @Override
   public Set<Entry<K, V>> entrySet()
   {
      return new ArrayMapEntrySet();
   }

   private int indexOfKey(K k)
   {
      for (int i = 0; i < size; i++)
         if (eq(keys[i], k))
            return i;
      return -1;
   }

   Entry<K, V> createEntry(final int index)
   {
      return new Entry<K, V>()
      {
         @Override
         public K getKey()
         {
            return ArrayMap.this.keys[index];
         }

         @Override
         public V getValue()
         {
            return ArrayMap.this.vals[index];
         }

         @Override
         public V setValue(V value)
         {
            V old = ArrayMap.this.vals[index];
            ArrayMap.this.vals[index] = value;
            return old;
         }

         @Override
         public boolean equals(Object obj)
         {
            if (!(obj instanceof Entry< ? , ? >))
               return false;
            Entry<K, V> e = (Entry<K, V>) obj;
            return eq(e.getKey(), this.getKey()) && eq(e.getValue(), this.getValue());
         }
      };
   }

   class ArrayMapEntrySet implements Set<Entry<K, V>>
   {
      @Override
      public boolean isEmpty()
      {
         return ArrayMap.this.isEmpty();
      }

      @Override
      public int size()
      {
         return ArrayMap.this.size();
      }

      @Override
      public boolean add(Entry<K, V> e)
      {
         return ArrayMap.this.put(e.getKey(), e.getValue()) != null;
      }

      @Override
      public boolean addAll(Collection< ? extends Entry<K, V>> c)
      {
         boolean changed = false;
         for (Entry<K, V> e : c)
            changed |= this.add(e);
         return changed;
      }

      @Override
      public boolean contains(Object o)
      {
         Entry<K, V> e = (Entry<K, V>) o;
         return eq(ArrayMap.this.get(e.getKey()), e.getValue());
      }

      @Override
      public boolean containsAll(Collection< ? > c)
      {
         for (Object o : c)
            if (!this.contains(o))
               return false;
         return true;
      }

      @Override
      public boolean remove(Object o)
      {
         return ArrayMap.this.remove(((Entry<K, V>) o).getKey()) != null;
      }

      @Override
      public boolean removeAll(Collection< ? > c)
      {
         boolean changed = false;
         for (Object o : c)
            changed |= this.remove(o);
         return changed;
      }

      @Override
      public boolean retainAll(Collection< ? > c)
      {
         boolean changed = false;
         for (int i = 0; i < ArrayMap.this.size; i++)
         {
            Entry<K, V> e = ArrayMap.this.createEntry(i);

            if (!c.contains(e))
            {
               ArrayMap.this.remove(e.getKey());
               changed = true;
               i -= 1;
            }
         }

         return changed;
      }

      @Override
      public void clear()
      {
         ArrayMap.this.clear();
      }

      @Override
      public Iterator<Entry<K, V>> iterator()
      {
         return new ArrayMapEntryIterator();
      }

      @Override
      public <T> T[] toArray(T[] a)
      {
         int size = this.size();
         if (a.length < size)
            a = ArrayUtil.growTo(a, size);
         for (int i = 0; i < a.length; i++)
            a[i] = (T) ArrayMap.this.createEntry(i);
         if (size != a.length)
            a[size] = null;
         return a;
      }

      @Override
      public Object[] toArray()
      {
         Object[] arr = new Object[this.size()];
         for (int i = 0; i < arr.length; i++)
            arr[i] = ArrayMap.this.createEntry(i);
         return arr;
      }
   }

   class ArrayMapEntryIterator implements Iterator<Entry<K, V>>
   {
      private int index     = -1;
      boolean     canRemove = false;

      public boolean hasNext()
      {
         return (index + 1) < ArrayMap.this.size;
      }

      public Map.Entry<K, V> next()
      {
         if (!this.hasNext())
            throw new NoSuchElementException();
         index += 1;
         this.canRemove = true;
         return ArrayMap.this.createEntry(index);
      }

      public void remove()
      {
         if (!this.canRemove)
            throw new NoSuchElementException();
         ArrayMap.this.remove(ArrayMap.this.keys[index]);
         this.canRemove = false;
         index -= 1;
      }
   }

   static final boolean eq(Object a, Object b)
   {
      if (a == b)
         return true;
      if (a == null || b == null)
         return false;
      return a.equals(b);
   }
}