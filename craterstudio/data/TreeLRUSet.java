/*
 * Created on 12 okt 2009
 */

package craterstudio.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import java.util.Map.Entry;

public class TreeLRUSet<T> implements LRUSet<T>
{
   private final int                 elems;
   private int                       birth;
   private final HashMap<T, Integer> objToBirth;
   private final TreeMap<Integer, T> birthToObj;

   public TreeLRUSet(int elems)
   {
      this.elems = elems;
      this.objToBirth = new HashMap<T, Integer>();
      this.birthToObj = new TreeMap<Integer, T>();
      this.birth = 0;
   }

   @Override
   public int size()
   {
      return this.objToBirth.size();
   }

   @Override
   public int capacity()
   {
      return this.elems;
   }

   @Override
   public T put(T elem)
   {
      if (elem == null)
      {
         throw new NullPointerException("null values not supported");
      }

      T removed;

      Integer birthObj = this.objToBirth.get(elem);
      if (birthObj != null)
      {
         // remove current
         this.objToBirth.remove(elem);
         this.birthToObj.remove(birthObj);

         removed = null;
      }
      else if (this.objToBirth.size() >= this.elems)
      {
         // remove oldest
         Entry<Integer, T> entry = this.birthToObj.firstEntry();
         birthObj = entry.getKey();
         T oldest = entry.getValue();

         this.birthToObj.remove(birthObj);
         this.objToBirth.remove(oldest);

         removed = oldest;
      }
      else
      {
         removed = null;
      }

      this.birth += 1;

      // add current
      this.objToBirth.put(elem, Integer.valueOf(this.birth));
      this.birthToObj.put(Integer.valueOf(this.birth), elem);

      return removed;
   }

   @Override
   public boolean contains(T elem)
   {
      return this.objToBirth.containsKey(elem);
   }

   @Override
   public boolean remove(T elem)
   {
      Integer birthObj = this.objToBirth.remove(elem);
      if (birthObj == null)
         return false;
      this.birthToObj.remove(birthObj);
      return true;
   }

   @Override
   public Iterator<T> iterator()
   {
      List<T> elems = new ArrayList<T>();
      elems.addAll(this.objToBirth.keySet());
      return Collections.unmodifiableCollection(elems).iterator();
   }

   /**
    * 
    */
   public void clear()
   {
      this.objToBirth.clear();
      this.birthToObj.clear();
   }
}