/*
 * Created on 1 jan 2008
 */

package craterstudio.util;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.Map.Entry;

public class NonNullHashMap<K, V> extends HashMap<K, V>
{
   private final HashMap<K, V> backing = new HashMap<K, V>();

   @Override
   public V put(K key, V val)
   {
      if (key == null || val == null)
         throw new NullPointerException("key=" + key + ", val=" + val);
      return backing.put(key, val);
   }

   @Override
   public void putAll(Map< ? extends K, ? extends V> map)
   {
      for (K key : map.keySet())
         this.put(key, map.get(key));
   }

   @Override
   public V get(Object key)
   {
      V v = backing.get(key);
      if (v == null)
         throw new NoSuchElementException("No such key: " + key);
      return v;
   }

   @Override
   public void clear()
   {
      backing.clear();
   }

   @Override
   public boolean containsKey(Object key)
   {
      return backing.containsKey(key);
   }

   @Override
   public boolean containsValue(Object value)
   {
      return backing.containsValue(value);
   }

   @Override
   public Set<Entry<K, V>> entrySet()
   {
      return backing.entrySet();
   }

   @Override
   public boolean equals(Object o)
   {
      return backing.equals(o);
   }

   @Override
   public boolean isEmpty()
   {
      return backing.isEmpty();
   }

   @Override
   public Set<K> keySet()
   {
      return backing.keySet();
   }

   @Override
   public V remove(Object key)
   {
      if (!backing.containsKey(key))
         throw new NullPointerException("No such key: " + key);
      return backing.remove(key);
   }

   @Override
   public int size()
   {
      return backing.size();
   }

   @Override
   public Collection<V> values()
   {
      return backing.values();
   }

   @Override
   public String toString()
   {
      return backing.toString();
   }
}