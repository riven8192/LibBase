/*
 * Created on 25-apr-2007
 */

package craterstudio.util;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ArrayUtil
{
   public static <T> void randomSelection(List<T> input, int elements, List<T> output)
   {
      if (input.size() <= elements)
         throw new IllegalStateException();
      if (!output.isEmpty())
         throw new IllegalStateException();

      int[] mapping = new int[input.size()];
      for (int i = 0; i < mapping.length; i++)
         mapping[i] = i;

      Random r = new Random();
      for (int len = mapping.length; len > elements; len--)
         mapping[r.nextInt(len)] = mapping[len - 1];

      if (output instanceof ArrayList< ? >)
         ((ArrayList<T>) output).ensureCapacity(elements);
      for (int i = 0; i < elements; i++)
         output.add(input.get(mapping[i]));
   }

   public static void shuffle(int[] values)
   {
      shuffle(values, new Random());
   }

   public static void shuffle(int[] values, Random r)
   {
      for (int i = 0; i < values.length; i++)
      {
         int from = i;
         int to = from + r.nextInt(values.length - from);

         int holder = values[to];
         values[to] = values[from];
         values[from] = holder;
      }
   }

   public static <T> T[] randomSelection(T[] input, int elements)
   {
      int[] mapping = new int[input.length];
      for (int i = 0; i < mapping.length; i++)
         mapping[i] = i;

      Random r = new Random();
      for (int len = mapping.length; len > elements; len--)
         mapping[r.nextInt(len)] = mapping[len - 1];

      T[] output = (T[]) new Object[elements];
      for (int i = 0; i < elements; i++)
         output[i] = input[mapping[i]];
      return output;
   }

   public static void swap(Object[] array, int a, int b)
   {
      ArrayUtil.swap(array, a, b, array.length);
   }

   public static void swap(Object[] array, int a, int b, int max)
   {
      if (((a | b) < 0) || (a >= max) || (b >= max) || (max > array.length))
         throw new IllegalArgumentException();

      Object t = array[b];
      array[b] = array[a];
      array[a] = t;
   }

   // boolean[]

   public static final boolean[] growBy(boolean[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final boolean[] growTo(boolean[] src, int capacity)
   {
      boolean[] dst = new boolean[capacity];
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final boolean[] copyRange(boolean[] src, int off, int len)
   {
      boolean[] dst = new boolean[len];
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final boolean[] join(boolean[]... sets)
   {
      if (sets.length == 0)
         return new boolean[0];
      int sum = 0;
      for (boolean[] set : sets)
         sum += set.length;
      boolean[] full = new boolean[sum];
      int off = 0;
      for (boolean[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOf(boolean[] arr, boolean val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   // byte[]

   public static final byte[] growBy(byte[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final byte[] growTo(byte[] src, int capacity)
   {
      byte[] dst = new byte[capacity];
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final byte[] copyRange(byte[] src, int off, int len)
   {
      byte[] dst = new byte[len];
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final byte[] join(byte[]... sets)
   {
      if (sets.length == 0)
         return new byte[0];

      int sum = 0;
      for (byte[] set : sets)
         sum += set.length;
      byte[] full = new byte[sum];

      int off = 0;
      for (byte[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOf(byte[] arr, byte val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   // short[]

   public static final short[] growBy(short[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final short[] growTo(short[] src, int capacity)
   {
      short[] dst = new short[capacity];
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final short[] copyRange(short[] src, int off, int len)
   {
      short[] dst = new short[len];
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final short[] join(short[]... sets)
   {
      if (sets.length == 0)
         return new short[0];
      int sum = 0;
      for (short[] set : sets)
         sum += set.length;
      short[] full = new short[sum];
      int off = 0;
      for (short[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOf(short[] arr, short val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   // char[]

   public static final char[] growBy(char[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final char[] growTo(char[] src, int capacity)
   {
      char[] dst = new char[capacity];
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final char[] copyRange(char[] src, int off, int len)
   {
      char[] dst = new char[len];
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final char[] join(char[]... sets)
   {
      if (sets.length == 0)
         return new char[0];
      int sum = 0;
      for (char[] set : sets)
         sum += set.length;
      char[] full = new char[sum];
      int off = 0;
      for (char[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOf(char[] arr, char val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   // int[]

   public static final int[] growBy(int[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final int[] growTo(int[] src, int capacity)
   {
      int[] dst = new int[capacity];
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final int[] copyRange(int[] src, int off, int len)
   {
      int[] dst = new int[len];
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final int[] join(int[]... sets)
   {
      if (sets.length == 0)
         return new int[0];
      int sum = 0;
      for (int[] set : sets)
         sum += set.length;
      int[] full = new int[sum];
      int off = 0;
      for (int[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOf(int[] arr, int val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   public static final int[] splice(int[] src, int index, int... insert)
   {
      int[] tmp = new int[src.length + insert.length];
      System.arraycopy(src, 0, tmp, 0, index);
      System.arraycopy(insert, 0, tmp, index, insert.length);
      System.arraycopy(src, index, tmp, index + insert.length, src.length - index);
      return tmp;
   }

   // long[]

   public static final long[] growBy(long[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final long[] growTo(long[] src, int capacity)
   {
      long[] dst = new long[capacity];
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final long[] copyRange(long[] src, int off, int len)
   {
      long[] dst = new long[len];
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final long[] join(long[]... sets)
   {
      if (sets.length == 0)
         return new long[0];
      int sum = 0;
      for (long[] set : sets)
         sum += set.length;
      long[] full = new long[sum];
      int off = 0;
      for (long[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOf(long[] arr, long val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   // float[]

   public static final float[] growBy(float[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final float[] growTo(float[] src, int capacity)
   {
      float[] dst = new float[capacity];
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final float[] copyRange(float[] src, int off, int len)
   {
      float[] dst = new float[len];
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final float[] join(float[]... sets)
   {
      if (sets.length == 0)
         return new float[0];
      int sum = 0;
      for (float[] set : sets)
         sum += set.length;
      float[] full = new float[sum];
      int off = 0;
      for (float[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOf(float[] arr, float val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   // double[]

   public static final double[] growBy(double[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final double[] growTo(double[] src, int capacity)
   {
      double[] dst = new double[capacity];
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final double[] copyRange(double[] src, int off, int len)
   {
      double[] dst = new double[len];
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final double[] join(double[]... sets)
   {
      if (sets.length == 0)
         return new double[0];
      int sum = 0;
      for (double[] set : sets)
         sum += set.length;
      double[] full = new double[sum];
      int off = 0;
      for (double[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOf(double[] arr, double val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   // T[]

   public static final <T> T[] growBy(T[] src, int inc)
   {
      return growTo(src, src.length + inc);
   }

   public static final <T> T[] growTo(T[] src, int capacity)
   {
      // T[] dst = (T[]) Array.newInstance(src.getClass().getComponentType(),
      // capacity);
      T[] dst = (T[]) ArrayUtil.alloc(src.getClass().getComponentType(), capacity);
      System.arraycopy(src, 0, dst, 0, src.length);
      return dst;
   }

   public static final Object[] join(Object[]... sets)
   {
      if (sets.length == 0)
         return new Object[0];
      int sum = 0;
      for (Object[] set : sets)
         sum += set.length;
      Object[] full = new Object[sum];
      int off = 0;
      for (Object[] set : sets)
      {
         System.arraycopy(set, 0, full, off, set.length);
         off += set.length;
      }
      return full;
   }

   public static final int indexOfIdentity(Object[] arr, Object val)
   {
      for (int i = 0; i < arr.length; i++)
         if (arr[i] == val)
            return i;
      return -1;
   }

   public static final int indexOfEquals(Object[] arr, Object val)
   {
      if (val == null)
         return indexOfIdentity(arr, val);

      for (int i = 0; i < arr.length; i++)
         if (val.equals(arr[i]))
            return i;
      return -1;
   }

   public static final <T> T[] insert(T[] src, int index, T... insert)
   {
      T[] tmp = (T[]) Array.newInstance(src.getClass().getComponentType(), src.length + insert.length);
      System.arraycopy(src, 0, tmp, 0, index);
      System.arraycopy(insert, 0, tmp, index, insert.length);
      System.arraycopy(src, index, tmp, index + insert.length, src.length - index);
      return tmp;
   }

   public static final <T> T[] remove(T[] src, int index, int elements)
   {
      T[] tmp = (T[]) Array.newInstance(src.getClass().getComponentType(), src.length - elements);
      System.arraycopy(src, 0, tmp, 0, index);
      System.arraycopy(src, index + 1, tmp, index, src.length - index - elements);
      return tmp;
   }

   public static final <T> T[] ensure(T[] src, int minCapacity)
   {
      if (src.length >= minCapacity)
         return src;
      return growTo(src, minCapacity);
   }

   public static final <T> T[] ensure(T[] src, int minCapacity, float factor)
   {
      if (src.length >= minCapacity)
      {
         return src;
      }

      int newCapacity = src.length + 1;
      do
      {
         newCapacity *= factor;
      }
      while (newCapacity < minCapacity);

      return growTo(src, newCapacity);
   }

   public static final <T> T[] copyRange(T[] src, int off, int len)
   {
      T[] dst = (T[]) Array.newInstance(src.getClass().getComponentType(), len);
      System.arraycopy(src, off, dst, 0, len);
      return dst;
   }

   public static final <T> T[] join(T[] a, T[] b)
   {
      return join(a, 0, a.length, b, 0, b.length);
   }

   public static final <T> T[] join(T[] a, int aOff, int aLen, T[] b, int bOff, int bLen)
   {
      T[] dst = (T[]) Array.newInstance(a.getClass().getComponentType(), aLen + bLen);
      System.arraycopy(a, aOff, dst, 0, aLen);
      System.arraycopy(b, bOff, dst, aLen, bLen);
      return dst;
   }

   // util

   public static final <T> T[] alloc(Class<T> t, int capacity)
   {
      return (T[]) Array.newInstance(t, capacity);
   }
}