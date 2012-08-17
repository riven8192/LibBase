/*
 * Created on 8 jul 2008
 */

package craterstudio.util;

import java.util.Arrays;
import java.util.NoSuchElementException;

public class Bag<T>
{
   private T[] data;
   private int size;

   public Bag()
   {
      this(4);
   }

   public Bag(int space)
   {
      this.data = (T[]) new Object[space];
   }

   public void put(T t)
   {
      if (this.size == this.data.length)
      {
         this.data = Arrays.copyOf(this.data, Math.max((int) (this.size * 1.75f), 8));
      }

      this.data[size++] = t;
   }

   public void putAll(Bag<T> bag)
   {
      if (bag.size == 0)
         return;

      int reqSize = this.size + bag.size;
      if (this.data.length < reqSize)
      {
         // calculate new length
         int makeSize = this.data.length;
         while (makeSize < reqSize)
            makeSize = Math.max((int) (makeSize * 1.75f), 8);

         // create array, copy elements
         this.data = Arrays.copyOf(this.data, makeSize);
      }

      // copy 'remote' elements to own array
      System.arraycopy(bag.data, 0, this.data, this.size, bag.size);
      this.size += bag.size;
   }

   public T get(int i)
   {
      if (i >= size)
         throw new ArrayIndexOutOfBoundsException();
      return data[i];
   }

   public T take(int i)
   {
      if (i >= size)
         throw new ArrayIndexOutOfBoundsException();

      T took = data[i];
      data[i] = data[--size];
      data[size] = null;
      return took;
   }

   public T take(T t)
   {
      int i = this.indexOf(t);
      if (i == -1)
         throw new NoSuchElementException();
      return this.take(i);
   }

   public void fillArray(T[] holder)
   {
      if (holder == null || holder.length < this.size)
         throw new IllegalStateException();
      System.arraycopy(this.data, 0, holder, 0, size);
   }

   public boolean contains(T t)
   {
      return this.indexOf(t) != -1;
   }

   public int indexOf(T t)
   {
      for (int i = 0; i < size; i++)
         if (data[i] == t)
            return i;
      return -1;
   }

   public void shrink()
   {
      if (this.data.length > 8)
      {
         int factor = 4;

         if (this.size < this.data.length / factor)
         {
            int newSize = Math.max(4, this.size);
            T[] newData = (T[]) new Object[newSize];
            System.arraycopy(this.data, 0, newData, 0, this.size);
            this.data = newData;
         }
      }
   }

   public void clear()
   {
      for (int i = 0; i < size; i++)
         data[i] = null;
      this.size = 0;
   }

   public int capacity()
   {
      return this.data.length;
   }

   public int size()
   {
      return size;
   }
}
