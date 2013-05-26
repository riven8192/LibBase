/*
 * Created on May 6, 2009
 */

package craterstudio.math;

class CacheItem
{
   public CacheItem(float xpos, float ypos, float zpos)
   {
      this.xpos = xpos;
      this.ypos = ypos;
      this.zpos = zpos;
   }

   float position;
   float xpos, ypos, zpos;
   float travelled;
}