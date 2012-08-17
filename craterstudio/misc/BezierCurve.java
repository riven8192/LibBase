/*
 * Created on 20 jul 2009
 */

package craterstudio.misc;

import craterstudio.math.Vec2;

public class BezierCurve
{
   public static Vec2 interpolate4(float t, Vec2 p1, Vec2 p2, Vec2 p3, Vec2 p4)
   {
      float invT = 1.0f - t;

      float m1 = pow3(invT) * 1.0f * pow0(t);
      float m2 = pow2(invT) * 3.0f * pow1(t);
      float m3 = pow1(invT) * 3.0f * pow2(t);
      float m4 = pow0(invT) * 1.0f * pow3(t);

      float x = 0.0f;
      float y = 0.0f;

      x += p1.x * m1;
      y += p1.y * m1;

      x += p2.x * m2;
      y += p2.y * m2;

      x += p3.x * m3;
      y += p3.y * m3;

      x += p4.x * m4;
      y += p4.y * m4;

      return new Vec2(x, y);
   }

   public static Vec2 interpolate(float t, Vec2... ps)
   {
      float x = 0.0f;
      float y = 0.0f;

      final int n = ps.length - 1;

      for (int k = 0; k <= n; k++)
      {
         float m = (float) (pow(1.0f - t, n - k) * combinatorialCoefficient(n, k) * pow(t, k));

         x += ps[k].x * m;
         y += ps[k].y * m;
      }

      return new Vec2(x, y);
   }

   private static float pow(float t, int times)
   {
      float tt = 1.0f;
      for (int i = 0; i < times; i++)
         tt *= t;
      return tt;
   }

   @SuppressWarnings("unused")
   private static float pow0(float t)
   {
      return 1.0f;
   }

   private static float pow1(float t)
   {
      return t;
   }

   private static float pow2(float t)
   {
      return t * t;
   }

   private static float pow3(float t)
   {
      return t * t * t;
   }

   public static double combinatorialCoefficient(int n, int k)
   {
      return factorial(n) / (factorial(k) * factorial(n - k));
   }

   public static double factorial(int n)
   {
      if (n >= 0 && n < factorial_lookup_table.length)
         return factorial_lookup_table[n];

      double val = 1.0;
      for (int i = 2; i <= n; i++)
         val *= i;
      return val;
   }

   //

   static final double[] factorial_lookup_table;
   static
   {
      // {1, 1, 2, 6, 24, 120, 720, ..., 1.31405e+502}
      factorial_lookup_table = new double[255];
      factorial_lookup_table[0] = 1.0;
      for (int i = 1; i < factorial_lookup_table.length; i++)
         factorial_lookup_table[i] = (factorial_lookup_table[i - 1] * i);
   }
}