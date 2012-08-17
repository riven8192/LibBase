/*
 * Created on 29-apr-2007
 */

package craterstudio.util;

public class Hasher
{
   public static final int hash(byte key, int bits)
   {
      int mask = ~(-1 << bits);

      int hash = 0;
      for (int shift = 0; shift < 8; shift += bits)
         hash ^= (key >> shift) & mask;
      return hash;
   }

   public static final int hash(short key, int bits)
   {
      int mask = ~(-1 << bits);

      int hash = 0;
      for (int shift = 0; shift < 16; shift += bits)
         hash ^= (key >> shift) & mask;
      return hash;
   }
   
   public static final int hash(char key, int bits)
   {
      int mask = ~(-1 << bits);

      int hash = 0;
      for (int shift = 0; shift < 16; shift += bits)
         hash ^= (key >> shift) & mask;
      return hash;
   }


   public static final int hash(int key, int bits)
   {
      int mask = ~(-1 << bits);

      int hash = 0;
      for (int shift = 0; shift < 32; shift += bits)
         hash ^= (key >> shift) & mask;
      return hash;
   }

   public static final int hash(long key, int bits)
   {
      int mask = ~(-1 << bits);

      int hash = 0;
      for (int shift = 0; shift < 64; shift += bits)
         hash ^= (key >> shift) & mask;
      return hash;
   }

   //

   public static final int hash(float key, int bits)
   {
      return hash(Float.floatToRawIntBits(key), bits);
   }

   public static final int hash(double key, int bits)
   {
      return hash(Double.doubleToRawLongBits(key), bits);
   }

   public static final int hash(Object key, int bits)
   {
      return hash(key.hashCode(), bits);
   }
   
   //
   
   public static final int hash(byte[] arr, int off, int len, int bits)
   {
      int hash = 0;
      for(int i=0; i<len; i++)
         hash ^= hash(arr[off+i], bits);
      return hash;
   }
   
   public static final int hash(short[] arr, int off, int len, int bits)
   {
      int hash = 0;
      for(int i=0; i<len; i++)
         hash ^= hash(arr[off+i], bits);
      return hash;
   }
   
   public static final int hash(char[] arr, int off, int len, int bits)
   {
      int hash = 0;
      for(int i=0; i<len; i++)
         hash ^= hash(arr[off+i], bits);
      return hash;
   }
   
   public static final int hash(int[] arr, int off, int len, int bits)
   {
      int hash = 0;
      for(int i=0; i<len; i++)
         hash ^= hash(arr[off+i], bits);
      return hash;
   }
   
   public static final int hash(long[] arr, int off, int len, int bits)
   {
      int hash = 0;
      for(int i=0; i<len; i++)
         hash ^= hash(arr[off+i], bits);
      return hash;
   }
   
   public static final int hash(float[] arr, int off, int len, int bits)
   {
      int hash = 0;
      for(int i=0; i<len; i++)
         hash ^= hash(arr[off+i], bits);
      return hash;
   }
   
   public static final int hash(double[] arr, int off, int len, int bits)
   {
      int hash = 0;
      for(int i=0; i<len; i++)
         hash ^= hash(arr[off+i], bits);
      return hash;
   }
   
   public static final int hash(Object[] arr, int off, int len, int bits)
   {
      int hash = 0;
      for(int i=0; i<len; i++)
         hash ^= hash(arr[off+i], bits);
      return hash;
   }
}
