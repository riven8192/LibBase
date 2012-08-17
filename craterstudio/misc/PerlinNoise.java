/**
 * Created on Jan 5, 2004
 */

package craterstudio.misc;

public class PerlinNoise
{
   private float xo, yo, zo;

   public final void offset(float x, float y, float z)
   {
      this.xo = x;
      this.yo = y;
      this.zo = z;
   }

   //

   public final float noise1D(float x, int octave)
   {
      float p = 1 << octave;
      return this.noise1D(x * p + this.xo) / p;
   }

   public final float noise2D(float x, float y, int octave)
   {
      float p = 1 << octave;
      return this.noise2D(x * p + this.xo, y * p + this.yo) / p;
   }

   public final float noise3D(float x, float y, float z, int octave)
   {
      float p = 1 << octave;
      return this.noise3D(x * p + this.xo, y * p + this.yo, z * p + this.zo) / p;
   }

   //

   public final float noise1D(float x)
   {
      float fx = floor(x);

      int gx = (int) fx & 0xFF;

      float u = fade(x -= fx);

      int a0 = perm[gx + 0];
      int b0 = perm[gx + 1];
      int aa = perm[a0 + 0];
      int ba = perm[b0 + 0];

      float a7 = grad(perm[ba + 0], x - 1, 0, 0);
      float a8 = grad(perm[aa + 0], x - 0, 0, 0);

      return lerp(u, a8, a7);
   }

   public final float noise2D(float x, float y)
   {
      float fx = floor(x);
      float fy = floor(y);

      int gx = (int) fx & 0xFF;
      int gy = (int) fy & 0xFF;

      float u = fade(x -= fx);
      float v = fade(y -= fy);

      int a0 = perm[gx + 0] + gy;
      int b0 = perm[gx + 1] + gy;
      int aa = perm[a0 + 0];
      int ab = perm[a0 + 1];
      int ba = perm[b0 + 0];
      int bb = perm[b0 + 1];

      float a5 = grad(perm[bb + 0], x - 1, y - 1, 0);
      float a6 = grad(perm[ab + 0], x - 0, y - 1, 0);
      float a7 = grad(perm[ba + 0], x - 1, y - 0, 0);
      float a8 = grad(perm[aa + 0], x - 0, y - 0, 0);

      float a6_5 = lerp(u, a6, a5);
      float a8_7 = lerp(u, a8, a7);
      float a8_5 = lerp(v, a8_7, a6_5);

      return a8_5;
   }

   public static void main(String[] args)
   {
      float[] p = new float[32768];

      int pow = 5;
      int bits, mask, elems, i, x, y, z;
      bits = 1 << pow;
      mask = bits - 1;
      elems = bits * bits * bits;
      System.out.println(elems);
      int pow0 = pow << 0;
      int pow1 = pow << 1;
      int pow2 = pow << 2;

      PerlinNoise pn = new PerlinNoise();

      for (int m = 0; m < 4; m++)
      {
         long t0 = System.nanoTime();
         for (int k = 0; k < 64; k++)
         {
            for (i = elems - 1; i >= 0; i--)
            {
               x = (i >> pow0) & mask;
               y = (i >> pow1) & mask;
               z = (i >> pow2) & mask;

               p[i] = pn.noise3D(x * 0.01f, y * 0.01f, z * 0.01f);
            }
         }
         long t1 = System.nanoTime();
         System.out.println("took: " + (t1 - t0) / 1000000L + "ms");

         float sum = 0.0f;
         for (i = elems - 1; i >= 0; i--)
            sum += p[i];
         System.out.println("dummy:" + sum);
      }
   }

   public final float noise3D(float x, float y, float z)
   {
      int ix = (int) x;
      int iy = (int) y;
      int iz = (int) z;
      x -= ix;
      y -= iy;
      z -= iz;
      int gx = ix & 0xFF;
      int gy = iy & 0xFF;
      int gz = iz & 0xFF;

      float u = fade(x);
      float v = fade(y);
      float w = fade(z);

      int a0 = perm[gx + 0] + gy;
      int b0 = perm[gx + 1] + gy;
      int aa = perm[a0 + 0] + gz;
      int ab = perm[a0 + 1] + gz;
      int ba = perm[b0 + 0] + gz;
      int bb = perm[b0 + 1] + gz;

      float a1 = grad(perm[bb + 1], x - 1, y - 1, z - 1);
      float a2 = grad(perm[ab + 1], x - 0, y - 1, z - 1);
      float a3 = grad(perm[ba + 1], x - 1, y - 0, z - 1);
      float a4 = grad(perm[aa + 1], x - 0, y - 0, z - 1);
      float a5 = grad(perm[bb + 0], x - 1, y - 1, z - 0);
      float a6 = grad(perm[ab + 0], x - 0, y - 1, z - 0);
      float a7 = grad(perm[ba + 0], x - 1, y - 0, z - 0);
      float a8 = grad(perm[aa + 0], x - 0, y - 0, z - 0);

      float a2_1 = lerp(u, a2, a1);
      float a4_3 = lerp(u, a4, a3);
      float a6_5 = lerp(u, a6, a5);
      float a8_7 = lerp(u, a8, a7);
      float a8_5 = lerp(v, a8_7, a6_5);
      float a4_1 = lerp(v, a4_3, a2_1);
      float a8_1 = lerp(w, a8_5, a4_1);

      return a8_1;
   }

   //

   private static final float floor(float v)
   {
      return (int) v;
   }

   private static final float fade(float t)
   {
      return t * t * t * (t * (t * 6.0f - 15.0f) + 10.0f);
   }

   private static final float lerp(float t, float a, float b)
   {
      return a + t * (b - a);
   }

   private static final float grad(int hash, float x, float y, float z)
   {
      int h = hash & 15;
      float u = (h < 8) ? x : y;
      float v = (h < 4) ? y : ((h == 12 || h == 14) ? x : z);
      return ((h & 1) == 0 ? u : -u) + ((h & 2) == 0 ? v : -v);
   }

   private static final int[] perm = new int[512];

   static
   {
      int[] permutation = { 151, 160, 137, 91, 90, 15, 131, 13, 201, 95, 96, 53, 194, 233, 7, 225, 140, 36, 103, 30, 69, 142, 8, 99, 37, 240, 21, 10, 23, 190, 6, 148, 247, 120, 234, 75, 0, 26, 197, 62, 94, 252, 219, 203, 117, 35, 11, 32, 57, 177, 33, 88, 237, 149, 56, 87, 174, 20, 125, 136, 171, 168, 68, 175, 74, 165, 71, 134, 139, 48, 27, 166, 77, 146, 158, 231, 83, 111, 229, 122, 60, 211, 133, 230, 220, 105, 92, 41, 55, 46, 245, 40, 244, 102, 143, 54, 65, 25, 63, 161, 1, 216, 80, 73, 209, 76, 132, 187, 208, 89, 18, 169, 200, 196, 135, 130, 116, 188, 159, 86, 164, 100, 109, 198, 173, 186, 3, 64, 52, 217, 226, 250, 124, 123, 5, 202, 38, 147, 118, 126, 255, 82, 85, 212, 207, 206, 59, 227, 47, 16, 58, 17, 182, 189, 28, 42, 223, 183, 170, 213, 119, 248, 152, 2, 44, 154, 163, 70, 221, 153, 101, 155, 167, 43, 172, 9, 129, 22, 39, 253, 19, 98, 108, 110, 79, 113, 224, 232, 178, 185, 112, 104, 218, 246, 97, 228, 251, 34, 242, 193, 238, 210, 144, 12, 191, 179, 162, 241, 81, 51, 145, 235, 249,
         14, 239, 107, 49, 192, 214, 31, 181, 199, 106, 157, 184, 84, 204, 176, 115, 121, 50, 45, 127, 4, 150, 254, 138, 236, 205, 93, 222, 114, 67, 29, 24, 72, 243, 141, 128, 195, 78, 66, 215, 61, 156, 180 };

      if (permutation.length != 256)
         throw new IllegalStateException();

      for (int i = 0; i < 256; i++)
         perm[256 + i] = perm[i] = permutation[i];
   }
}