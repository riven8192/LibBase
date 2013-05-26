/*
 * Created on Sep 23, 2005
 */

package craterstudio.math;

import java.util.ArrayList;
import java.util.List;

public class Spline2D
{
   public Spline2D(float[][] points)
   {
      this.count = points.length;

      float[] x = new float[count];
      float[] y = new float[count];

      for (int i = 0; i < count; i++)
      {
         x[i] = points[i][0];
         y[i] = points[i][1];
      }

      this.x = Curve.calcCurve(count - 1, x);
      this.y = Curve.calcCurve(count - 1, y);
   }

   //

   final int count;
   private final Cubic[] x, y;

   /**
    * POINT COUNT
    */

   public final int pointCount()
   {
      return count;
   }

   /**
    * POSITION
    */

   public final float[] getPositionAt(float param)
   {
      float[] v = new float[2];
      this.getPositionAt(param, v);
      return v;
   }

   public final void getPositionAt(float param, float[] result)
   {
      // clamp
      if (param < 0.0f)
         param = 0.0f;
      if (param >= count - 1)
         param = (count - 1) - Math.ulp(count - 1);

      // split
      int ti = (int) param;
      float tf = param - ti;

      // eval
      result[0] = x[ti].eval(tf);
      result[1] = y[ti].eval(tf);
   }

   private List<CacheItem> travelCache;
   private float           maxTravelStep;
   private float           posStep;

   public void enabledTripCaching(float maxTravelStep, float positionStep)
   {
      this.maxTravelStep = maxTravelStep;
      this.posStep = positionStep;

      float x = this.x[0].eval(0.0f);
      float y = this.y[0].eval(0.0f);

      this.travelCache = new ArrayList<CacheItem>();
      this.travelCache.add(new CacheItem(x, y, 0.0f));
   }

   private float length = -1.0f;

   public float calcLength(float stepSize)
   {
      if (this.length < 0.0f)
         this.length = this.getSteppingPosition(0.0f, Integer.MAX_VALUE, stepSize).travelled;
      return this.length;
   }

   public boolean getTripPosition(float totalTrip, float[] coords)
   {
      boolean isValid = true;

      CacheItem last = this.travelCache.get(this.travelCache.size() - 1);

      // build cache
      while (last.travelled < totalTrip)
      {
         if (totalTrip == 0.0f)
         {
            // don't even bother
            break;
         }

         float travel = Math.min(totalTrip - last.travelled, maxTravelStep);

         CacheItem curr = this.getSteppingPosition(last.position, travel, posStep);

         if (curr.position >= this.count)
         {
            // reached end of spline
            isValid = false;
            break;
         }

         // only cache if we travelled far enough
         if (curr.travelled > this.maxTravelStep * 0.95f)
         {
            this.travelCache.add(curr);
         }

         curr.travelled += last.travelled;

         last = curr;
      }

      // figure out position

      int lo = 0;
      int hi = this.travelCache.size() - 1;

      while (true)
      {
         int mid = (lo + hi) / 2;

         last = this.travelCache.get(mid);

         if (last.travelled < totalTrip)
         {
            if (lo == mid)
               break;
            lo = mid;
         }
         else
         {
            if (hi == mid)
               break;
            hi = mid;
         }
      }

      for (int i = lo; i <= hi; i++)
      {
         CacheItem item = this.travelCache.get(i);

         if (item.travelled <= totalTrip)
         {
            last = item;
         }
         else
         {
            break;
         }
      }

      float travel = totalTrip - last.travelled;
      last = this.getSteppingPosition(last.position, travel, posStep);
      coords[0] = last.xpos;
      coords[1] = last.ypos;

      return isValid;
   }

   private CacheItem getSteppingPosition(float positionOffset, float travel, float positionStep)
   {
      float totalTravelled = 0.0f;
      float currentPosition = positionOffset;
      float[] last = this.getPositionAt(currentPosition);

      while (totalTravelled < travel && currentPosition < this.count)
      {
         currentPosition += positionStep;
         float[] curr = this.getPositionAt(currentPosition);
         float justTravelled = Spline2D.dist(last, curr);
         totalTravelled += justTravelled;
         last = curr;
      }

      CacheItem item = new CacheItem(last[0], last[1], 0.0f);
      item.position = currentPosition;
      item.travelled = totalTravelled;
      return item;
   }

   private static float dist(float[] a, float[] b)
   {
      float dx = b[0] - a[0];
      float dy = b[1] - a[1];

      return (float) Math.sqrt(dx * dx + dy * dy);
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
         Cubic[] c = new Cubic[n + 0];

         // gamma
         gamma[0] = 0.5f;
         for (int i = 1; i < n; i++)
            gamma[i] = 1.0f / (4.0f - gamma[i - 1]);
         gamma[n] = 1.0f / (2.0f - gamma[n - 1]);

         // delta
         delta[0] = 3.0f * (axis[1] - axis[0]) * gamma[0];
         for (int i = 1; i < n; i++)
            delta[i] = (3.0f * (axis[i + 1] - axis[i - 1]) - delta[i - 1]) * gamma[i];
         delta[n] = (3.0f * (axis[n] - axis[n - 1]) - delta[n - 1]) * gamma[n];

         // d
         d[n] = delta[n];
         for (int i = n - 1; i >= 0; i--)
            d[i] = delta[i] - gamma[i] * d[i + 1];

         // c
         for (int i = 0; i < n; i++)
         {
            float x0 = axis[i + 0];
            float x1 = axis[i + 1];
            float d0 = d[i + 0];
            float d1 = d[i + 1];
            c[i] = new Cubic(x0, d0, 3.0f * (x1 - x0) - 2.0f * d0 - d1, 2.0f * (x0 - x1) + d0 + d1);
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