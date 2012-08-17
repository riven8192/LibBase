/*
 * Created on 8-jul-2007
 */

package craterstudio.math;

public class Vec4
{
   public float x, y, z, w;

   public Vec4()
   {
      this(0.0f, 0.0f, 0.0f, 0.0f);
   }

   public Vec4(float x, float y, float z, float w)
   {
      this.x = x;
      this.y = y;
      this.z = z;
      this.w = w;
   }
}
