package craterstudio.math;


public class ShapeMath2D
{

   /**
    * LINE <-> CIRCLE
    */

   public static boolean lineHitsCircle(Vec2 p1, Vec2 p2, Vec2 origin, float radius)
   {
      float x1 = p1.x - origin.x;
      float y1 = p1.y - origin.y;
      float x2 = p2.x - origin.x;
      float y2 = p2.y - origin.y;

      float dx = x2 - x1;
      float dy = y2 - y1;
      float dr2 = dx * dx + dy * dy;
      float r2 = radius * radius;
      float D = x1 * y2 - x2 * y1;
      float i = r2 * dr2 - D * D;

      return i >= 0.0f;
   }

   /**
    * LINE <-> LINE
    */

   private static final Vec2 tmpR = new Vec2();



   public static boolean lineHitsLine2D(Vec2 p1, Vec2 p2, Vec2 p3, Vec2 p4, boolean capped)
   {
      return ShapeMath2D.lineHitsLine2D(p1, p2, p3, p4, tmpR, capped) != null;
   }



   public static Vec2 lineHitsLine2D(Vec2 p1, Vec2 p2, Vec2 p3, Vec2 p4, Vec2 r, boolean capped)
   {
      float x1 = p1.x;
      float y1 = p1.y;
      float x2 = p2.x;
      float y2 = p2.y;
      float x3 = p3.x;
      float y3 = p3.y;
      float x4 = p4.x;
      float y4 = p4.y;

      float a1 = y2 - y1;
      float b1 = x1 - x2;
      float a2 = y4 - y3;
      float b2 = x3 - x4;

      float c1 = (x2 * y1) - (x1 * y2);
      float c2 = (x4 * y3) - (x3 * y4);

      float denom = (a1 * b2) - (a2 * b1);

      if (EasyMath.equals(denom, 0.0f, 0.0001f))
         return null;

      float xR = (b1 * c2 - b2 * c1) / denom;
      float yR = (a2 * c1 - a1 * c2) / denom;

      if (capped)
      {
         if (x1 > x2)
         {
            if (xR < x1 || xR > x2)
               return null;
         }
         else
         {
            if (xR < x2 || xR > x1)
               return null;
         }

         if (y1 < y2)
         {
            if (yR < y1 || yR > y2)
               return null;
         }
         else
         {
            if (yR < y2 || yR > y1)
               return null;
         }
      }

      r.x = xR;
      r.y = yR;

      return r;
   }



   /**
    * POINT IN TRIANGLE
    */

   public static boolean isPointInTriangle2D(Vec2 p, Vec2 a, Vec2 b, Vec2 c)
   {
      float xBA, yBA, xPA, yPA;
      xBA = b.x - a.x;
      yBA = b.y - a.y;
      xPA = p.x - a.x;
      yPA = p.y - a.y;
      boolean sideA = (yBA * xPA - xBA * yPA) > 0.0f;

      float xCB, yCB, xPB, yPB;
      xCB = c.x - b.x;
      yCB = c.y - b.y;
      xPB = p.x - b.x;
      yPB = p.y - b.y;
      boolean sideB = (yCB * xPB - xCB * yPB) > 0.0f;

      if (sideA != sideB)
         return false;

      float xAC, yAC, xPC, yPC;
      xAC = a.x - c.x;
      yAC = a.y - c.y;
      xPC = p.x - c.x;
      yPC = p.y - c.y;
      boolean sideC = (yAC * xPC - xAC * yPC) > 0.0f;

      return (sideA == sideC);
   }

}
