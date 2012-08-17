/*
 * Created on 5-aug-2006
 */

package craterstudio.math;


public class Triangle
{
   public final Vec3 p1, p2, p3;

   public Triangle()
   {
      this(new Vec3(), new Vec3(), new Vec3());
   }

   public Triangle(Vec3 p1, Vec3 p2, Vec3 p3)
   {
      this.p1 = p1;
      this.p2 = p2;
      this.p3 = p3;
   }

   public String toString()
   {
      return "Triangle[" + p1 + ", " + p2 + ", " + p3 + "]";
   }
}
