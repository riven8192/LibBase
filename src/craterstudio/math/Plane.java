/*
 * Created on 21-sep-2006
 */

package craterstudio.math;

import static craterstudio.math.VecMath.*;

public class Plane
{
   public final Vec3 origin, normal;

   public Plane(Vec3 normal, float d)
   {
      this.origin = new Vec3(normal).length(d);
      this.normal = normal;
   }

   public Plane(Vec3 origin, Vec3 normal)
   {
      this.origin = origin;
      this.normal = normal;
   }

   public Plane(Triangle t)
   {
      this.origin = t.p1;
      this.normal = normal(t.p1, t.p2, t.p3);
   }

   public final Vec3 intersection(Ray ray, Vec3 pos)
   {
      float px = this.origin.x;
      float py = this.origin.y;
      float pz = this.origin.z;

      float nx = this.normal.x;
      float ny = this.normal.y;
      float nz = this.normal.z;

      float rx = ray.origin.x;
      float ry = ray.origin.y;
      float rz = ray.origin.z;

      float dx = ray.direction.x;
      float dy = ray.direction.y;
      float dz = ray.direction.z;

      //

      float x = rx - px;
      float y = ry - py;
      float z = rz - pz;

      float v0 = -x * nx - y * ny - z * nz;
      float vd = dx * nx + dy * ny + dz * nz;
      float v0_vd = v0 / vd;

      //

      pos.x = (dx * v0_vd + rx);
      pos.y = (dy * v0_vd + ry);
      pos.z = (dz * v0_vd + rz);

      return pos;
   }

   public final void reflection(Ray src, Ray dst)
   {
      float px = this.origin.x;
      float py = this.origin.y;
      float pz = this.origin.z;

      float nx = this.normal.x;
      float ny = this.normal.y;
      float nz = this.normal.z;

      float rx = src.origin.x;
      float ry = src.origin.y;
      float rz = src.origin.z;

      float dx = src.direction.x;
      float dy = src.direction.y;
      float dz = src.direction.z;

      //

      float src1x = rx - px;
      float src1y = ry - py;
      float src1z = rz - pz;
      float d2_1 = (src1x * nx + src1y * ny + src1z * nz) * 2.0f;
      float dst1x = px + nx * d2_1 - src1x;
      float dst1y = py + ny * d2_1 - src1y;
      float dst1z = pz + nz * d2_1 - src1z;

      float src2x = src1x + dx;
      float src2y = src1y + dy;
      float src2z = src1z + dz;
      float d2_2 = (src2x * nx + src2y * ny + src2z * nz) * 2.0f;
      float dst2x = px + nx * d2_2 - src2x;
      float dst2y = py + ny * d2_2 - src2y;
      float dst2z = pz + nz * d2_2 - src2z;

      float v0 = -src1x * nx - src1y * ny - src1z * nz;
      float vd = dx * nx + dy * ny + dz * nz;
      float v0_vd = v0 / vd;

      //

      dst.origin.x = (dx * v0_vd + rx);
      dst.origin.y = (dy * v0_vd + ry);
      dst.origin.z = (dz * v0_vd + rz);

      dst.direction.x = (dst1x - dst2x);
      dst.direction.y = (dst1y - dst2y);
      dst.direction.z = (dst1z - dst2z);
   }

   public final Vec3 mirror(Vec3 src, Vec3 dst)
   {
      // src = this.src - this.origin
      // dot2 = dot(src, normal) * 2
      // dst = src - (normal * dot2) + origin

      float px = origin.x;
      float py = origin.y;
      float pz = origin.z;

      float nx = normal.x;
      float ny = normal.y;
      float nz = normal.z;

      float srcx = src.x - px;
      float srcy = src.y - py;
      float srcz = src.z - pz;

      float dot2 = (srcx * nx + srcy * ny + srcz * nz) * 2.0f;

      dst.x = (srcx - (nx * dot2) + px);
      dst.y = (srcy - (ny * dot2) + py);
      dst.z = (srcz - (nz * dot2) + pz);

      return dst;
   }

   public final boolean isAbove(Vec3 p)
   {
      return this.signedDistanceTo(p) >= 0.0f;
   }

   public final boolean isFrontFacingTo(Vec3 direction)
   {
      return dot(direction, normal) <= 0.0f;
   }

   public final float signedDistanceTo(Vec3 p)
   {
      // normal . (p - origin)

      float x = normal.x * (p.x - origin.x);
      float y = normal.y * (p.y - origin.y);
      float z = normal.z * (p.z - origin.z);

      return x + y + z;
   }

   public final Vec3 snapToPlane(Vec3 p, Vec3 r)
   {
      // p - normal * (normal . (p - origin))

      float dist = this.signedDistanceTo(p);
      r.x = (p.x - normal.x * dist);
      r.y = (p.y - normal.y * dist);
      r.z = (p.z - normal.z * dist);
      return r;
   }
}