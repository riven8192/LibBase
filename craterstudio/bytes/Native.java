/*
 * Created on 6-feb-2007
 */

package craterstudio.bytes;

import sun.misc.Unsafe;

public class Native
{
   private static final Unsafe unsafe;

   static
   {
      unsafe = NativeHacks.instance();
   }

   //

   public static final void zeroOut(long pointer, int bytes)
   {
      fillOut(pointer, bytes, (byte) 0);
   }

   public static final void fillOut(long pointer, int bytes, byte val)
   {
      long pntr = pointer - 1;
      long end = pointer + bytes;

      while (++pntr < end)
         bput(pntr, val);
   }

   //

   public static final int nativeBits()
   {
      return -1;
   }

   // -----------------------------------------------
   // --------------- array put/get -----------------
   // -----------------------------------------------

   // byte[]

   public static final void put(long p, byte[] src, int off, int len)
   {
      for (int i = 0; i < len; i++)
         bput(p + (i << 0), src[off + i]);
   }

   public static final void get(long p, byte[] dst, int off, int len)
   {
      for (int i = 0; i < len; i++)
         dst[off + i] = bget(p + (i << 0));
   }

   // short[]

   public static final void put(long p, short[] src, int off, int len)
   {
      for (int i = 0; i < len; i++)
         sput(p + (i << 1), src[off + i]);
   }

   public static final void get(long p, short[] dst, int off, int len)
   {
      for (int i = 0; i < len; i++)
         dst[off + i] = sget(p + (i << 1));
   }

   // int[]

   public static final void put(long p, int[] src, int off, int len)
   {
      for (int i = 0; i < len; i++)
         iput(p + (i << 2), src[off + i]);
   }

   public static final void get(long p, int[] dst, int off, int len)
   {
      for (int i = 0; i < len; i++)
         dst[off + i] = iget(p + (i << 2));
   }

   // long[]

   public static final void put(long p, long[] src, int off, int len)
   {
      for (int i = 0; i < len; i++)
         lput(p + (i << 3), src[off + i]);
   }

   public static final void get(long p, long[] dst, int off, int len)
   {
      for (int i = 0; i < len; i++)
         dst[off + i] = lget(p + (i << 3));
   }

   // float[]

   public static final void put(long p, float[] src, int off, int len)
   {
      for (int i = 0; i < len; i++)
         fput(p + (i << 2), src[off + i]);
   }

   public static final void get(long p, float[] dst, int off, int len)
   {
      for (int i = 0; i < len; i++)
         dst[off + i] = fget(p + (i << 2));
   }

   // double[]

   public static final void put(long p, double[] src, int off, int len)
   {
      for (int i = 0; i < len; i++)
         dput(p + (i << 3), src[off + i]);
   }

   public static final void get(long p, double[] dst, int off, int len)
   {
      for (int i = 0; i < len; i++)
         dst[off + i] = dget(p + (i << 3));
   }

   // -----------------------------------------------
   // --------------- bulk put/get -----------------
   // -----------------------------------------------

   public static final void copy(long src, long dst, long bytes)
   {
      unsafe.copyMemory(src, dst, bytes);
   }

   public static final void copyBytes(long src, long dst, int elements)
   {
      unsafe.copyMemory(src, dst, elements << 0);
   }

   public static final void copyShorts(long src, long dst, int elements)
   {
      unsafe.copyMemory(src, dst, elements << 1);
   }

   public static final void copyInts(long src, long dst, int elements)
   {
      unsafe.copyMemory(src, dst, elements << 2);
   }

   public static final void copyLongs(long src, long dst, int elements)
   {
      unsafe.copyMemory(src, dst, elements << 3);
   }

   public static final void copyFloats(long src, long dst, int elements)
   {
      unsafe.copyMemory(src, dst, elements << 2);
   }

   public static final void copyDoubles(long src, long dst, int elements)
   {
      unsafe.copyMemory(src, dst, elements << 3);
   }

   public static final void copyPages(long src, long dst, int elements)
   {
      unsafe.copyMemory(src, dst, elements * NativeAllocator.pageSize());
   }

   // -----------------------------------------------

   // byte

   public static final byte bget(byte[] data, int off)
   {
      return unsafe.getByte(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off);
   }

   public static final void bput(byte[] data, int off, byte val)
   {
      unsafe.putByte(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off, val);
   }

   public static final void bput(long p, byte v)
   {
      unsafe.putByte(p, v);
   }

   public static final byte bget(long p)
   {
      return unsafe.getByte(p);
   }

   // short

   public static final short sget(short[] data, int off)
   {
      return unsafe.getShort(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off);
   }

   public static final void sput(byte[] data, int off, short val)
   {
      unsafe.putShort(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off, val);
   }

   public static final void sput(long p, short v)
   {
      unsafe.putShort(p, v);
   }

   public static final short sget(long p)
   {
      return unsafe.getShort(p);
   }

   // char

   public static final void cput(long p, char v)
   {
      unsafe.putChar(p, v);
   }

   public static final char cget(long p)
   {
      return unsafe.getChar(p);
   }

   // int

   public static final int iget(byte[] data, int off)
   {
      return unsafe.getInt(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off);
   }

   public static final void iput(byte[] data, int off, int val)
   {
      unsafe.putInt(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off, val);
   }

   public static final void iput(long p, int v)
   {
      unsafe.putInt(p, v);
   }

   public static final int iget(long p)
   {
      return unsafe.getInt(p);
   }

   // long

   public static final long lget(byte[] data, int off)
   {
      return unsafe.getLong(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off);
   }

   public static final void lput(byte[] data, int off, long val)
   {
      unsafe.putLong(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off, val);
   }

   public static final void lput(long p, long v)
   {
      unsafe.putLong(p, v);
   }

   public static final long lget(long p)
   {
      return unsafe.getLong(p);
   }

   // float

   public static final float fget(byte[] data, int off)
   {
      return unsafe.getFloat(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off);
   }

   public static final void fput(byte[] data, int off, float val)
   {
      unsafe.putFloat(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off, val);
   }

   public static final void fput(long p, float v)
   {
      unsafe.putFloat(p, v);
   }

   public static final float fget(long p)
   {
      return unsafe.getFloat(p);
   }

   // double

   public static final double dget(byte[] data, int off)
   {
      return unsafe.getDouble(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off);
   }

   public static final void dput(byte[] data, int off, double val)
   {
      unsafe.putDouble(data, NativeHacks.BYTE_ARRAY_BASE_OFFSET + off, val);
   }

   public static final void dput(long p, double v)
   {
      unsafe.putDouble(p, v);
   }

   public static final double dget(long p)
   {
      return unsafe.getDouble(p);
   }

   // swap

   public static final short swap16(short val)
   {
      short swapped = 0;
      swapped |= (val & 0x00FF) << 8;
      swapped |= (val & 0xFF00) >> 8;
      return swapped;
   }

   public static final int swap32(int val)
   {
      int swapped = 0;
      swapped |= (val & 0x000000FF) << 24;
      swapped |= (val & 0x0000FF00) << 8;
      swapped |= (val & 0x00FF0000) >> 8;
      swapped |= (val & 0xFF000000) >>> 24;
      return swapped;
   }

   public static final long swap64(long val)
   {
      long swapped = 0;
      swapped |= (val & 0x00000000000000FFL) << 56;
      swapped |= (val & 0x000000000000FF00L) << 40;
      swapped |= (val & 0x0000000000FF0000L) << 24;
      swapped |= (val & 0x00000000FF000000L) << 8;
      swapped |= (val & 0x000000FF00000000L) >> 8;
      swapped |= (val & 0x0000FF0000000000L) >> 24;
      swapped |= (val & 0x00FF000000000000L) >> 40;
      swapped |= (val & 0xFF00000000000000L) >>> 56;
      return swapped;
   }
}