/*
 * Created on 15-dec-2004
 */
package craterstudio.math;

public class ArrayMath
{
   /**
    * COPY
    */

   public static final void copy(float[] src, float[] dst)
   {
      for (int i = 0; i < src.length; i++)
         dst[i] += src[i];
   }

   /**
    * ABS
    */

   public static final void abs(float[] data)
   {
      for (int i = 0; i < data.length; i++)
         data[i] = Math.abs(data[i]);
   }

   /**
    * ADD
    */

   public static final void add(float[] data, float value)
   {
      for (int i = 0; i < data.length; i++)
         data[i] += value;
   }

   public static final void add(float[] data, float[] value)
   {
      for (int i = 0; i < data.length; i++)
         data[i] += value[i];
   }

   public static final float diff(float[] a)
   {
      float sum = 0.0F;

      for (int i = 1; i < a.length; i++)
         sum += Math.abs(a[i - 1] - a[i]);

      return sum;
   }

   public static final float diff(float[] a, int off, int len)
   {
      float sum = 0.0F;

      for (int i = 1; i < len; i++)
         sum += Math.abs(a[off + i - 1] - a[off + i - 0]);

      return sum;
   }

   /**
    * DIFF
    */

   public static final float diff(float[] a, float[] b)
   {
      float sum = 0.0F;

      for (int i = 0; i < a.length; i++)
         sum += Math.abs(a[i] - b[i]);

      return sum;
   }

   /**
    * MUL
    */

   public static final void mul(float[] data, float value)
   {
      for (int i = 0; i < data.length; i++)
         data[i] *= value;
   }

   public static final void mul(float[] data, float[] value)
   {
      for (int i = 0; i < data.length; i++)
         data[i] *= value[i];
   }

   public static final void pow(float[] data)
   {
      for (int i = 0; i < data.length; i++)
         data[i] *= data[i];
   }

   public static final void sqrt(float[] data)
   {
      for (int i = 0; i < data.length; i++)
         data[i] = (float) Math.sqrt(data[i]);
   }

   /**
    * MIN/MAX
    */

   public static final void min(float[] data, float[] value)
   {
      for (int i = 0; i < data.length; i++)
         if (value[i] < data[i])
            data[i] = value[i];
   }

   public static final void max(float[] data, float[] value)
   {
      for (int i = 0; i < data.length; i++)
         if (value[i] > data[i])
            data[i] = value[i];
   }

   /**
    * EQUALS
    */

   public static final boolean equals(float[] a, float[] b, float delta)
   {
      for (int i = 0; i < a.length; i++)
         if (!EasyMath.equals(a[i], b[i], delta))
            return false;

      return true;
   }

   /**
    * SCAN
    */

   public static final float scanMipMap1D(float x, float[] data, int width, int step)
   {
      // Invalid
      if (width != data.length)
      {
         throw new IllegalArgumentException("width must be data.length");
      }

      if (x < 0.0F || x >= width - 1)
      {
         x = EasyMath.moduloInRange(x, 0.0F, width - 1);
      }

      // Snap
      final int xSnap = (int) (x) / step * step;

      if (xSnap == x)
      {
         return data[xSnap];
      }

      int xNext = EasyMath.clamp(xSnap + step, xSnap, width - 1);

      float w = data[xSnap];
      float e = data[xNext];

      // Offset: 0..step
      final float xSnapOffset = x - xSnap;

      return EasyMath.interpolate(xSnapOffset, 0.0F, step, w, e);
   }

   public static final float scanMipMap2D(float x, float z, float[] data, int width, int height, int step, boolean clamp)
   {
      // Invalid
      if (width * height != data.length)
      {
         throw new IllegalArgumentException("width*height must be data.length");
      }

      if (clamp)
      {
         x = EasyMath.clamp(x, 0.0F, width - 1);
         z = EasyMath.clamp(z, 0.0F, height - 1);
      }
      else
      {
         // repeat
         if (x < 0.0F || x >= width - 1)
            x = EasyMath.moduloInRange(x, 0.0F, width - 1);

         if (z < 0.0F || z >= height - 1)
            z = EasyMath.moduloInRange(z, 0.0F, height - 1);
      }

      // Snap
      final int xSnap = ((int) x) / step * step;
      final int zSnap = ((int) z) / step * step;

      if (xSnap == x && zSnap == z)
      {
         return data[zSnap * width + xSnap];
      }

      final int xNext = EasyMath.clamp(xSnap + step, xSnap, width - 1);
      final int zNext = EasyMath.clamp(zSnap + step, zSnap, width - 1);

      float nw = data[zSnap * width + xSnap];
      float ne = data[zSnap * width + xNext];
      float se = data[zNext * width + xNext];
      float sw = data[zNext * width + xSnap];

      // Offset: 0..step
      final float xSnapOffset = x - xSnap;
      final float zSnapOffset = z - zSnap;

      // Which triangle of quad (left | right)
      if (xSnapOffset > zSnapOffset)
         sw = nw + se - ne;
      else
         ne = se + nw - sw;

      float n = EasyMath.interpolate(xSnapOffset, 0.0F, step, nw, ne);
      float s = EasyMath.interpolate(xSnapOffset, 0.0F, step, sw, se);

      return EasyMath.interpolate(zSnapOffset, 0.0F, step, n, s);
   }

   public static final void minmax(float[] data, float[] result)
   {
      float min = Float.MAX_VALUE;
      float max = -min;

      for (int i = 0; i < data.length; i++)
      {
         if (min > data[i])
            min = data[i];

         if (max < data[i])
            max = data[i];
      }

      result[0] = min;
      result[1] = max;
   }

   public static final void makeSumOne(float[] data)
   {
      float total = 0.0f;
      for (int i = 0; i < data.length; i++)
         total += data[i];

      if (total == 0.0f)
         return;

      float inv_total = 1.0f / total;
      for (int i = 0; i < data.length; i++)
         data[i] *= inv_total;
   }

   public static void invPow(float[] data, int times)
   {
      if (times <= 0)
      {
         throw new IllegalArgumentException("times=" + times);
      }

      if (times == 1)
      {
         for (int i = 0; i < data.length; i++)
         {
            float d = data[i];
            d = 1.0f - d;
            d *= d;
            d = 1.0f - d;
            data[i] = d;
         }
      }
      else
      {
         for (int i = 0; i < data.length; i++)
         {
            float d = data[i];
            d = 1.0f - d;
            float dP = d;
            for (int t = 0; t < times; t++)
               dP *= d;
            d = dP;
            d = 1.0f - d;
            data[i] = d;
         }
      }
   }

   /**
    * NORMALIZE
    */

   public static final void normalize(float[] data)
   {
      ArrayMath.normalize(data, new float[2]);
   }

   public static final void normalize(float[] data, float[] rangeResult)
   {
      minmax(data, rangeResult);

      float min = rangeResult[0];
      float max = rangeResult[1];

      if (min == max)
      {
         for (int i = 0; i < data.length; i++)
            data[i] = 0.0f;
      }
      else
      {
         float invRange = 1.0F / (max - min);
         for (int i = 0; i < data.length; i++)
            data[i] = (data[i] - min) * invRange;
      }
   }

   public static final void normalizeRange(float[] data, float min, float max)
   {
      if (min == max)
      {
         for (int i = 0; i < data.length; i++)
            data[i] = 0.0f;
      }
      else
      {
         float invRange = 1.0f / (max - min);
         for (int i = 0; i < data.length; i++)
            data[i] = (data[i] - min) * invRange;
      }
   }

   public static final void normalize(float[][] data)
   {
      float[] minmax = new float[] { Integer.MAX_VALUE, Integer.MIN_VALUE };

      for (int i = 0; i < data.length; i++)
      {
         float[] result = new float[2];
         ArrayMath.minmax(data[i], result);
         if (result[0] < minmax[0])
            minmax[0] = result[0];
         if (result[1] > minmax[1])
            minmax[1] = result[1];
      }

      for (int i = 0; i < data.length; i++)
      {
         ArrayMath.normalizeRange(data[i], minmax[0], minmax[1]);
      }
   }

   public static void swap(int[] arr, int a, int b)
   {
      int t = arr[a];
      arr[a] = arr[b];
      arr[b] = t;
   }
}