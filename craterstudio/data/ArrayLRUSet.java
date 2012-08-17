/*
 * Created on 12 okt 2009
 */

package craterstudio.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class ArrayLRUSet<T> implements LRUSet<T>
{
   private final T[]   slots;
   private final int[] generation;
   private int         counter;
   private int         size;

   public ArrayLRUSet(int elems)
   {
      this.slots = (T[]) new Object[elems];
      this.generation = new int[elems];
      this.counter = 0;
      this.size = 0;
   }

   @Override
   public int size()
   {
      return this.size;
   }
   
   @Override
   public int capacity()
   {
      return this.slots.length;
   }

   @Override
   public T put(T elem)
   {
      if (elem == null)
      {
         throw new NullPointerException("null values not supported");
      }

      int io = this.indexOf(elem);
      T old = null;
      if (io == -1) // not found, overwrite oldest
      {
         io = this.indexOfLeastRecentlyUsed();
         old = this.slots[io];
         this.slots[io] = elem;
         if (old == null)
            this.size++;
      }
      this.generation[io] = ++this.counter;
      return old;
   }

   @Override
   public boolean contains(T elem)
   {
      return this.indexOf(elem) != -1;
   }

   @Override
   public boolean remove(T elem)
   {
      int io = this.indexOf(elem);
      if (io == -1)
         return false;
      this.slots[io] = null;
      this.generation[io] = 0;
      this.size--;
      return true;
   }

   @Override
   public Iterator<T> iterator()
   {
      List<T> elems = new ArrayList<T>();
      for (int i = 0; i < this.generation.length; i++)
         if (this.generation[i] > 0)
            elems.add(this.slots[i]);
      return Collections.unmodifiableCollection(elems).iterator();
   }

   @Override
   public void clear()
   {
      for (int i = 0; i < this.generation.length; i++)
      {
         this.slots[i] = null;
         this.generation[i] = 0;
      }
      this.counter = 0;
      this.size = 0;
   }

   private final int indexOf(T elem)
   {
      for (int i = 0; i < this.generation.length; i++)
         if (elem.equals(this.slots[i]))
            return i;
      return -1;
   }

   private final int indexOfLeastRecentlyUsed()
   {
      int index = 0;
      for (int i = 0; i < this.generation.length; i++)
         if (this.generation[i] < this.generation[index])
            index = i;
      return index;
   }
}