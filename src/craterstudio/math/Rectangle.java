/*
 * Created on 28-dec-2005
 */

package craterstudio.math;

public class Rectangle
{
   public final int x, y, w, h;

   public Rectangle(int x, int y, int w, int h)
   {
      this.x = x;
      this.y = y;
      this.w = w;
      this.h = h;
   }

   public final boolean contains(int x, int y)
   {
      return !(x < this.x || x > this.x + w || y < this.y || y > y + this.h);
   }

   public final int distance(int x, int y)
   {
      int dd = this.squaredDistance(x, y);
      if (dd == 0)
         return 0;
      return (int) Math.round(Math.sqrt(dd));
   }

   public final boolean isDistanceSmallerThan(int x, int y, int max)
   {
      return this.squaredDistance(x, y) < (max * max);
   }

   public final int squaredDistance(int x, int y)
   {
      int L = this.x - x;
      int R = x - (this.x + w);
      int T = this.y - y;
      int B = y - (this.y + h);

      boolean betweenX = L <= 0 && R <= 0;
      boolean betweenY = T <= 0 && B <= 0;

      // A B C
      // D E F
      // G H I

      if (betweenX && betweenY) // E
         return 0;

      if (betweenX)
      {
         if (T > 0)
            return T * T; // B
         if (B > 0)
            return B * B; // H
      }

      if (betweenY)
      {
         if (L > 0)
            return L * L; // D
         if (R > 0)
            return R * R; // F
      }

      if (T > 0)
      {
         if (L > 0)
            return T * T + L * L; // A
         return T * T + R * R; // C
      }
      if (L > 0)
         return B * B + L * L; // G
      return B * B + R * R; // I
   }
}
