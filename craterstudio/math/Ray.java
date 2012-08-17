/*
 * Created on 9-okt-2006
 */

package craterstudio.math;


public class Ray
{
   public final Vec3 origin, direction;

   public Ray(Vec3 origin, Vec3 direction)
   {
      this.origin = origin;
      this.direction = direction;
   }
}
