/*
 * Created on Jun 1, 2008
 */

package craterstudio.bytes;

import sun.misc.Unsafe;

public class NativeAllocator
{
   private static final Unsafe unsafe;

   static
   {
      unsafe = NativeHacks.instance();
   }

   //

   public static final void free(long pointer)
   {
      unsafe.freeMemory(pointer);
   }

   public static final int pageSize()
   {
      return unsafe.pageSize();
   }

   public static final long malloc(long bytes)
   {
      return unsafe.allocateMemory(bytes);
   }

   public static final long[] malloc_aligned(int bytes, int align)
   {
      long[] pntrs = new long[2];
      pntrs[0] = malloc(bytes + align);
      pntrs[1] = pntrs[0] + (align - (pntrs[0] % align));
      return pntrs;
   }

   //

   public static final long malloc_byte(int bytes)
   {
      return malloc_aligned(bytes << 0, 1 << 0)[1];
   }

   public static final long malloc_short(int shorts)
   {
      return malloc_aligned(shorts << 1, 1 << 1)[1];
   }

   public static final long malloc_int(int ints)
   {
      return malloc_aligned(ints << 2, 1 << 2)[1];
   }

   public static final long malloc_long(int longs)
   {
      return malloc_aligned(longs << 3, 1 << 3)[1];
   }

   public static final long malloc_float(int floats)
   {
      return malloc_aligned(floats << 2, 1 << 2)[1];
   }

   public static final long malloc_double(int doubles)
   {
      return malloc_aligned(doubles << 3, 1 << 3)[1];
   }

   public static final long malloc_page(int pages)
   {
      return malloc_aligned(pages * NativeAllocator.pageSize(), NativeAllocator.pageSize())[1];
   }

   //

   public static final long page_malloc_byte(int elements)
   {
      return malloc_aligned(elements << 0, pageSize())[1];
   }

   public static final long page_malloc_short(int elements)
   {
      return malloc_aligned(elements << 1, pageSize())[1];
   }

   public static final long page_malloc_int(int elements)
   {
      return malloc_aligned(elements << 2, pageSize())[1];
   }

   public static final long page_malloc_long(int elements)
   {
      return malloc_aligned(elements << 3, pageSize())[1];
   }

   public static final long page_malloc_float(int elements)
   {
      return malloc_aligned(elements << 2, pageSize())[1];
   }

   public static final long page_malloc_double(int elements)
   {
      return malloc_aligned(elements << 3, pageSize())[1];
   }
}
