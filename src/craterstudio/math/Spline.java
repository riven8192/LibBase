/*
 * Created on Sep 23, 2005
 */

package craterstudio.math;

import java.awt.*;

import javax.swing.*;


import java.util.Random;

public class Spline
{
   public static void main(String[] args)
   {
      Random r = new Random(128735L);
      Vec3[] vec = new Vec3[32];
      for (int i = 0; i < vec.length; i++)
         vec[i] = new Vec3(r.nextFloat(), r.nextFloat(), 0.0f).mul(512);

      final Spline spline = new Spline(vec);
      spline.setAccuracy(0.001f, 0.0001f);

      JPanel painter = new JPanel()
      {
         private static final long serialVersionUID = -1L;

         protected void paintComponent(Graphics g)
         {
            super.paintComponent(g);

            int segments = 1024 * 8;

            // t-based
            {
               g.setColor(Color.BLUE);
               Vec3 pos = new Vec3();
               Vec3 pos0 = new Vec3();
               spline.getPositionAt(0.0f, pos0);
               for (int i = 0; i < segments; i++)
               {
                  float part = (float) spline.n0 * i / segments;
                  spline.getPositionAt(part, pos);
                  g.drawLine((int) pos0.x, (int) pos0.y, (int) pos.x, (int) pos.y);
                  pos0.load(pos);
               }
            }
            // d-based
            {
               g.setColor(Color.RED);
               float len = spline.length();
               Vec3 pos = new Vec3();
               Vec3 pos0 = new Vec3();
               spline.getPositionAtDistance(0.0f, pos0);
               for (int i = 0; i < segments; i++)
               {
                  float part = len * i / segments;
                  spline.getPositionAtDistance(part, pos);
                  g.drawLine((int) pos0.x, (int) pos0.y, (int) pos.x, (int) pos.y);
                  pos0.load(pos);
               }
            }
         }
      };
      painter.setPreferredSize(new Dimension(512, 512));

      JFrame frame = new JFrame();
      frame.setLayout(new BorderLayout());
      frame.add(painter, BorderLayout.CENTER);
      frame.pack();
      frame.setVisible(true);
      frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
   }

   public Spline(Vec3[] points)
   {
      n0 = points.length;
      n1 = n0 - 1;

      float[] x = new float[n0];
      float[] y = new float[n0];
      float[] z = new float[n0];

      for (int i = 0; i < n0; i++)
      {
         x[i] = points[i].x;
         y[i] = points[i].y;
         z[i] = points[i].z;
      }

      this.x = Curve.calcCurve(n1, x);
      this.y = Curve.calcCurve(n1, y);
      this.z = Curve.calcCurve(n1, z);

      this.setAccuracy(0.01f, 0.01f);
   }

   final int n0, n1;
   private final Cubic[] x, y, z;
   private CacheTree     root;

   public final float distanceBetween(float t0, float t1)
   {
      float t = t0;

      Vec3 curr = this.getPositionAt(t);
      Vec3 prev = new Vec3(curr);

      float d = 0.0f;

      while (t < t1)
      {
         this.getPositionAt(t, curr);
         d += VecMath.distance(curr, prev);
         prev.load(curr);

         t += tStepSize;
      }

      return d;
   }

   /**
    * POINT COUNT
    */

   public final int pointCount()
   {
      return n0;
   }

   /**
    * POSITION
    */

   public final Vec3 getPositionAt(float param)
   {
      Vec3 v = new Vec3();
      this.getPositionAt(param, v);
      return v;
   }

   public final void getPositionAt(float param, Vec3 result)
   {
      // clamp
      if (param < 0.0F)
         param = 0.0F;
      if (param >= n1)
         param = n1 - 0.00001F;

      // split
      int ti = (int) param;
      float tf = param - ti;

      // eval
      result.x = x[ti].eval(tf);
      result.y = y[ti].eval(tf);
      result.z = z[ti].eval(tf);
   }

   /**
    * ANGLE AT
    */

   public final float getAngleAt(float t)
   {
      Vec3 a = getPositionAt(t - 0.01f);
      Vec3 b = getPositionAt(t + 0.01f);
      return -VecMath.angleToFlat3D(b, a);
   }

   public final float getAngleAtDistance(float dist)
   {
      Vec3 a = getPositionAtDistance(dist - 0.1f);
      Vec3 b = getPositionAtDistance(dist + 0.1f);
      return -VecMath.angleToFlat3D(b, a);
   }

   /**
    * ACCURACY
    */

   private float tStepSize     = 1.0f;
   private float marginOfError = 1.0f;

   public final void setAccuracy(float stepSize, float marginOfError)
   {
      this.tStepSize = stepSize;
      this.marginOfError = marginOfError;

      // clear all values stored in cache
      cachedLength = -1;
      root = new CacheTree();
   }

   /**
    * POSITION AT DISTANCE
    */

   public final Vec3 getPositionAtDistance(float dist)
   {
      Vec3 v = new Vec3();
      this.getPositionAtDistance(dist, v);
      return v;
   }

   public final void getPositionAtDistance(float dist, Vec3 result)
   {
         float t = 0.0f;

         Vec3 curr = this.getPositionAt(t);
         Vec3 prev = new Vec3(curr);

         float d = 0.0f;

         while (d < dist)
         {
            this.getPositionAt(t, curr);
            d += VecMath.distance(curr, prev);
            prev.load(curr);

            t += tStepSize;
         }

         this.getPositionAt(t, result);
   }

   private class CacheTree
   {
      final int depth;
      CacheTree subLo, subHi;
      final float dstLow, dstMid;
      final float tLo, tHf, tHi;

      CacheTree()
      {
         this.depth = 0;

         this.tLo = 0.0f;
         this.tHi = Spline.this.n1;
         this.dstLow = 0.0f;

         this.tHf = (tLo + tHi) * 0.5f;

         float range = Spline.this.distanceBetween(tLo, tHi);
         this.dstMid = dstLow + range * 0.5f;
      }

      CacheTree(CacheTree parent, boolean larger)
      {
         this.depth = parent.depth + 1;

         if (larger)
         {
            this.tLo = parent.tHf;
            this.tHi = parent.tHi;
            this.dstLow = parent.dstMid;
         }
         else
         {
            this.tLo = parent.tLo;
            this.tHi = parent.tHf;
            this.dstLow = parent.dstLow;
         }

         this.tHf = (tLo + tHi) * 0.5f;

         float range = Spline.this.distanceBetween(tLo, tHi);
         this.dstMid = dstLow + range * 0.5f;
      }

      static final int maxDepth = 10;

      public final CacheTree search(float dist)
      {
         if (dist < dstMid)
         {
            if (subLo == null)
            {
               if (depth == maxDepth)
                  return this;
               subLo = new CacheTree(this, false);
            }

            return subLo.search(dist);
         }

         if (subHi == null)
         {
            if (depth == maxDepth)
               return this;
            subHi = new CacheTree(this, true);
         }

         return subHi.search(dist);
      }
   }

   /**
    * LENGTH
    */

   private float cachedLength = -1;

   public final float length()
   {
      if (cachedLength < 0.0f)
         cachedLength = this.distanceBetween(0.0F, n1);
      return cachedLength;
   }

   /**
    * CURVE CLASS
    */

   private static class Curve
   {
      static final Cubic[] calcCurve(int n, float[] axis)
      {
         float[] gamma = new float[n + 1];
         float[] delta = new float[n + 1];
         float[] d = new float[n + 1];
         Cubic[] c = new Cubic[n];

         // gamma
         gamma[0] = 0.5F;
         for (int i = 1; i < n; i++)
            gamma[i] = 1.0F / (4.0F - gamma[i - 1]);
         gamma[n] = 1.0F / (2.0F - gamma[n - 1]);

         // delta
         delta[0] = 3.0F * (axis[1] - axis[0]) * gamma[0];
         for (int i = 1; i < n; i++)
            delta[i] = (3.0F * (axis[i + 1] - axis[i - 1]) - delta[i - 1]) * gamma[i];
         delta[n] = (3.0F * (axis[n] - axis[n - 1]) - delta[n - 1]) * gamma[n];

         // d
         d[n] = delta[n];
         for (int i = n - 1; i >= 0; i--)
            d[i] = delta[i] - gamma[i] * d[i + 1];

         // c
         for (int i = 0; i < n; i++)
         {
            float x0 = axis[i];
            float x1 = axis[i + 1];
            float d0 = d[i];
            float d1 = d[i + 1];
            c[i] = new Cubic(x0, d0, 3.0F * (x1 - x0) - 2.0F * d0 - d1, 2.0F * (x0 - x1) + d0 + d1);
         }
         return c;
      }
   }

   /**
    * CUBIC CLASS
    */

   static class Cubic
   {
      private final float a, b, c, d;

      Cubic(float a, float b, float c, float d)
      {
         this.a = a;
         this.b = b;
         this.c = c;
         this.d = d;
      }

      final float eval(float u)
      {
         return (((d * u) + c) * u + b) * u + a;
      }
   }
}