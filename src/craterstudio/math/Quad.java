/*
 * Created on 5-aug-2006
 */

package craterstudio.math;


public class Quad
{
   public final Vec3 p1, p2, p3, p4;

   public Quad()
   {
      this(new Vec3(), new Vec3(), new Vec3(), new Vec3());
   }

   public Quad(Vec3 p1, Vec3 p2, Vec3 p3, Vec3 p4)
   {
      this.p1 = p1;
      this.p2 = p2;
      this.p3 = p3;
      this.p4 = p4;
   }
}
