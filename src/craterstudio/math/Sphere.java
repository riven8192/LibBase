/*
 * Created on 5-aug-2006
 */

package craterstudio.math;

public class Sphere
{
   public Sphere()
   {
      this(0, 0, 0, 0);
   }

   public Sphere(float x, float y, float z, float radius)
   {
      this.origin.load(x, y, z);
      this.radius = radius;
   }

   public Sphere(Sphere s)
   {
      this.origin.load(s.origin);
      this.radius = s.radius;
   }

   public Vec3  origin = new Vec3();
   public float radius;

   public final void load(float x, float y, float z, float radius)
   {
      this.origin.load(x, y, z);
      this.radius = radius;
   }

   public final void load(Sphere that)
   {
      this.origin.load(that.origin);
      this.radius = that.radius;
   }

   public String toString()
   {
      return "Sphere[origin=" + origin + ",radius=" + radius + "]";
   }
}