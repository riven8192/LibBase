/*
 * Created on Aug 15, 2008
 */

package craterstudio.util;

import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

public class ArraySet<E> implements Set<E>
{
   public static void main(String[] args)
   {
      ArraySet<String> set = new ArraySet<String>();

      if (set.size() != 0)
         throw new IllegalStateException();

      set.add(new String("hello"));
      if (set.size() != 1)
         throw new IllegalStateException();
      if (!HighLevel.iteratorElement(set.iterator(), 0).equals("hello"))
         throw new IllegalStateException();

      if (!set.contains(new String("hello")))
         throw new IllegalStateException();

      if (set.add(new String("hello")))
         throw new IllegalStateException();
      if (set.size() != 1)
         throw new IllegalStateException();

      if (!set.add(new String("bye")))
         throw new IllegalStateException();
      if (set.size() != 2)
         throw new IllegalStateException();

      if (set.remove("cya"))
         throw new IllegalStateException();

      if (!set.remove("hello"))
         throw new IllegalStateException();
      if (set.size() != 1)
         throw new IllegalStateException();
      if (!HighLevel.iteratorElement(set.iterator(), 0).equals("bye"))
         throw new IllegalStateException();

      System.out.println("done");
   }

   private E[] elems;
   private int size;

   public ArraySet()
   {
      elems = (E[]) new Object[4];
   }

   public void prioritize(E e)
   {
      int i = this.indexOfElem(e);
      if (i == -1)
         throw new NoSuchElementException();
      if (i == 0)
         return;
      ArrayUtil.swap(this.elems, 0, i);
   }

   @Override
   public void clear()
   {
      for (int i = 0; i < size; i++)
         elems[i] = null;
      size = 0;
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
   public boolean add(E e)
   {
      int i = this.indexOfElem(e);
      if (i != -1)
         return false;

      if (size == elems.length)
         elems = ArrayUtil.growBy(elems, size);

      elems[size] = e;
      size++;
      return true;
   }

   @Override
   public boolean addAll(Collection< ? extends E> s)
   {
      boolean changed = false;
      for (E e : s)
         changed |= this.add(e);
      return changed;
   }

   @Override
   public boolean contains(Object e)
   {
      return this.indexOfElem((E) e) != -1;
   }

   @Override
   public boolean containsAll(Collection< ? > s)
   {
      for (Object e : s)
         if (!this.contains(e))
            return false;
      return true;
   }

   @Override
   public boolean remove(Object e)
   {
      int i = this.indexOfElem((E) e);
      if (i == -1)
         return false;

      this.removeAt(i);

      return true;
   }

   private final void removeAt(int i)
   {
      int newSize = size - 1;

      if (i != newSize)
      {
         ArrayUtil.swap(this.elems, i, newSize, this.size);
         elems[newSize] = null;
      }

      size = newSize;
   }

   @Override
   public boolean removeAll(Collection< ? > s)
   {
      boolean changed = false;
      for (Object e : s)
         changed |= this.remove(e);
      return changed;
   }

   @Override
   public boolean retainAll(Collection< ? > s)
   {
      boolean changed = false;
      for (int i = 0; i < size; i++)
      {
         if (!s.contains(this.elems[i]))
         {
            this.removeAt(i);
            changed = true;
            i -= 1;
         }
      }
      return changed;
   }

   @Override
   public Object[] toArray()
   {
      Object[] arr = new Object[this.size()];
      System.arraycopy(this.elems, 0, arr, 0, size);
      return arr;
   }

   @Override
   public <V> V[] toArray(V[] a)
   {
      int size = this.size();
      if (a.length < size)
         a = ArrayUtil.growTo(a, size);
      System.arraycopy(this.elems, 0, a, 0, size);
      if (size != a.length)
         a[size] = null;
      return a;
   }

   private int indexOfElem(E e)
   {
      for (int i = 0; i < size; i++)
         if (eq(elems[i], e))
            return i;
      return -1;
   }

   @Override
   public Iterator<E> iterator()
   {
      return IteratorUtil.iterator(this.elems, 0, this.size);
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