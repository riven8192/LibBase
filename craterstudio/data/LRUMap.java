/*
 * Created on 22 jun 2009
 */

package craterstudio.data;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Map.Entry;

public class LRUMap<K, V>
{
   private final LRUSet<K> lruKeys;
   private final Map<K, V> map;
   private final Map<K, V> dumped;

   public LRUMap(int size)
   {
      this(size, false);
   }

   public LRUMap(int size, boolean doDump)
   {
      this.lruKeys = new TreeLRUSet<K>(size);
      this.map = new HashMap<K, V>();
      this.dumped = doDump ? new HashMap<K, V>() : null;
   }

   public V put(K key, V value)
   {
      this.doTouch(key);

      return this.map.put(key, value);
   }

   public void touch(K key)
   {
      if (!this.map.containsKey(key))
      {
         throw new NoSuchElementException("key: " + key);
      }

      this.doTouch(key);
   }

   public boolean contains(K key)
   {
      if (!this.map.containsKey(key))
      {
         return false;
      }

      this.doTouch(key);
      return true;
   }

   public V get(K key)
   {
      if (!this.map.containsKey(key))
      {
         return null;
      }

      this.doTouch(key);
      return this.map.get(key);
   }

   public V remove(K key)
   {
      if (!this.map.containsKey(key))
      {
         return null;
      }

      this.lruKeys.remove(key);
      return this.map.remove(key);
   }

   public Entry<K, V> takeDumped()
   {
      Iterator<Entry<K, V>> it = this.dumped.entrySet().iterator();
      return it.hasNext() ? it.next() : null;
   }

   public Map<K, V> drainDumped()
   {
      Map<K, V> result = new HashMap<K, V>();

      result.putAll(this.dumped);
      this.dumped.clear();

      return result;
   }

   public Map<K, V> drain(boolean all)
   {
      Map<K, V> result = new HashMap<K, V>();

      if (this.dumped != null)
      {
         result.putAll(this.dumped);
         this.dumped.clear();
      }

      if (all)
      {
         result.putAll(this.map);
      }

      return result;
   }

   public void clear()
   {
      this.map.clear();
      this.lruKeys.clear();
   }

   private final K doTouch(K key)
   {
      K removedKey = this.lruKeys.put(key);

      if (removedKey != null && this.dumped != null)
      {
         V removedValue = this.map.remove(removedKey);
         this.dumped.put(removedKey, removedValue);
      }

      return removedKey;
   }

   final Iterable<K> keys()
   {
      return this.map.keySet();
   }
}