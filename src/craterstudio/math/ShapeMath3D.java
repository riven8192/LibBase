/*
 * Created on 14-aug-2006
 */

package craterstudio.math;

import static craterstudio.bytes.Native.*;
import static craterstudio.math.VecMath.*;

public class ShapeMath3D
{
   public static final Sphere sphereAroundCube(Vec3 min, Vec3 max, Sphere target)
   {
      target.origin.load(min).add(max).mul(0.5f);
      target.radius = Math.max(max.x - min.x, Math.max(max.y - min.y, max.z - min.z));
      target.radius *= 0.5f * (float) Math.sqrt(3);
      return target;
   }

   public static final Vec3 intersectionPointWithRay(Plane plane, Ray ray, Vec3 result)
   {
      float normal_x = plane.normal.x;
      float normal_y = plane.normal.y;
      float normal_z = plane.normal.z;

      // d = plane.origin - ray.origin
      float d_x = plane.origin.x - ray.origin.x;
      float d_y = plane.origin.y - ray.origin.y;
      float d_z = plane.origin.z - ray.origin.z;

      // dot1 = dot(normal, d)
      // dot2 = dot(normal, ray.direction)
      float dot1 = normal_x * d_x + normal_y * d_y + normal_z * d_z;
      float dot2 = normal_x * ray.direction.x + normal_y * ray.direction.y + normal_z * ray.direction.z;
      float dot1dot2 = dot1 / dot2;

      // result = ray.direction * dot1dot2 + ray.origin
      result.x = (ray.direction.x * dot1dot2 + ray.origin.x);
      result.y = (ray.direction.y * dot1dot2 + ray.origin.y);
      result.z = (ray.direction.z * dot1dot2 + ray.origin.z);

      return result;
   }

   public static final boolean intersectionWithTriangle(Triangle t, Ray ray)
   {
      Vec3 a = t.p1;
      Vec3 b = t.p2;
      Vec3 c = t.p3;

      float a_x = a.x;
      float a_y = a.y;
      float a_z = a.z;
      float b_x = b.x;
      float b_y = b.y;
      float b_z = b.z;
      float c_x = c.x;
      float c_y = c.y;
      float c_z = c.z;

      // q = b - a
      float qx = b_x - a_x;
      float qy = b_y - a_y;
      float qz = b_z - a_z;

      // p = c - a
      float px = c_x - a_x;
      float py = c_y - a_y;
      float pz = c_z - a_z;

      // normal = cross(q, p)
      float normal_x = qy * pz - qz * py;
      float normal_y = qz * px - qx * pz;
      float normal_z = qx * py - qy * px;

      // normalize (normal)
      float li = 1.0f / (float) Math.sqrt(normal_x * normal_x + normal_y * normal_y + normal_z * normal_z);
      normal_x *= li;
      normal_y *= li;
      normal_z *= li;

      // 

      // d = a - ray.origin
      float d_x = a_x - ray.origin.x;
      float d_y = a_y - ray.origin.y;
      float d_z = a_z - ray.origin.z;

      float dot1 = normal_x * d_x + normal_y * d_y + normal_z * d_z;
      float dot2 = normal_x * ray.direction.x + normal_y * ray.direction.y + normal_z * ray.direction.z;
      float dot1dot2 = dot1 / dot2;

      // p = ray.direction * dot1dot2 + ray.origin
      float p_x = ray.direction.x * dot1dot2 + ray.origin.x;
      float p_y = ray.direction.y * dot1dot2 + ray.origin.y;
      float p_z = ray.direction.z * dot1dot2 + ray.origin.z;

      // tmp001 = a - c
      float tmp001_x = a_x - c_x;
      float tmp001_y = a_y - c_y;
      float tmp001_z = a_z - c_z;

      // tmp002 = p - c
      float tmp002_x = p_x - c_x;
      float tmp002_y = p_y - c_y;
      float tmp002_z = p_z - c_z;

      // tmp003 = cross(tmp001, tmp002)
      float tmp003_x = (tmp001_y * tmp002_z) - (tmp001_z * tmp002_y);
      float tmp003_y = (tmp001_z * tmp002_x) - (tmp001_x * tmp002_z);
      float tmp003_z = (tmp001_x * tmp002_y) - (tmp001_y * tmp002_x);

      // tmp004 = dot(tmp003, normal)
      float tmp004 = (tmp003_x * normal_x) + (tmp003_y * normal_y) + (tmp003_z * normal_z);
      if (tmp004 < 0.0f)
         return false;

      // tmp005 = b - a
      float tmp005_x = b_x - a_x;
      float tmp005_y = b_y - a_y;
      float tmp005_z = b_z - a_z;

      // tmp006 = p - a
      float tmp006_x = p_x - a_x;
      float tmp006_y = p_y - a_y;
      float tmp006_z = p_z - a_z;

      // tmp007 = cross(tmp005, tmp006)
      float tmp007_x = (tmp005_y * tmp006_z) - (tmp005_z * tmp006_y);
      float tmp007_y = (tmp005_z * tmp006_x) - (tmp005_x * tmp006_z);
      float tmp007_z = (tmp005_x * tmp006_y) - (tmp005_y * tmp006_x);

      // tmp008 = dot(tmp007, normal)
      float tmp008 = (tmp007_x * normal_x) + (tmp007_y * normal_y) + (tmp007_z * normal_z);
      if (tmp008 < 0.0f)
         return false;

      // tmp009 = c - b
      float tmp009_x = c_x - b_x;
      float tmp009_y = c_y - b_y;
      float tmp009_z = c_z - b_z;

      // tmp010 = p - b
      float tmp010_x = p_x - b_x;
      float tmp010_y = p_y - b_y;
      float tmp010_z = p_z - b_z;

      // tmp011 = cross(tmp009, tmp010)
      float tmp011_x = (tmp009_y * tmp010_z) - (tmp009_z * tmp010_y);
      float tmp011_y = (tmp009_z * tmp010_x) - (tmp009_x * tmp010_z);
      float tmp011_z = (tmp009_x * tmp010_y) - (tmp009_y * tmp010_x);

      // tmp012 = dot(tmp011, normal)
      float tmp012 = (tmp011_x * normal_x) + (tmp011_y * normal_y) + (tmp011_z * normal_z);
      if (tmp012 < 0.0f)
         return false;

      return true;
   }

   /**
    * LINE <-> SPHERE
    */

   public static boolean infiniteLineHitsSphere(Vec3 p1, Vec3 p2, Sphere sphere)
   {
      return infiniteLineHitsSphere(p1, p2, sphere.origin, sphere.radius);
   }

   public static boolean infiniteLineHitsSphere(Vec3 p1, Vec3 p2, Vec3 p3, float r)
   {
      float x1 = p1.x;
      float y1 = p1.y;
      float z1 = p1.z;

      float x2 = p2.x;
      float y2 = p2.y;
      float z2 = p2.z;

      float x3 = p3.x;
      float y3 = p3.y;
      float z3 = p3.z;

      // diff between line-points
      float x21 = x2 - x1;
      float y21 = y2 - y1;
      float z21 = z2 - z1;

      // diff between first line-point and sphere origin
      float x13 = x1 - x3;
      float y13 = y1 - y3;
      float z13 = z1 - z3;

      // y = ax^2 + bx + c
      float a = x21 * x21 + y21 * y21 + z21 * z21;
      float b = 2.0f * ((x21 * x13) + (y21 * y13) + (z21 * z13));
      float c = (x3 * x3) + (y3 * y3) + (z3 * z3);
      c += (x1 * x1) + (y1 * y1) + (z1 * z1);
      c -= 2.0f * (x3 * x1 + y3 * y1 + z3 * z1);
      c -= r * r;

      // b^2 - 4ac
      float determ = b * b - 4.0f * a * c;

      return (determ >= 0.0f);
   }

   public static boolean lineHitsSphere(Vec3 p1, Vec3 p2, Sphere sphere)
   {
      return lineHitsSphere(p1, p2, sphere.origin, sphere.radius);
   }

   public static boolean lineHitsSphere(Vec3 p1, Vec3 p2, Vec3 p3, float r)
   {
      float x1 = p1.x;
      float y1 = p1.y;
      float z1 = p1.z;

      float x2 = p2.x;
      float y2 = p2.y;
      float z2 = p2.z;

      float x3 = p3.x;
      float y3 = p3.y;
      float z3 = p3.z;

      // diff between line-points
      float x21 = x2 - x1;
      float y21 = y2 - y1;
      float z21 = z2 - z1;

      // diff between first line-point and sphere origin
      float x13 = x1 - x3;
      float y13 = y1 - y3;
      float z13 = z1 - z3;

      // y = ax^2 + bx + c
      float a = x21 * x21 + y21 * y21 + z21 * z21;
      float b = 2.0f * ((x21 * x13) + (y21 * y13) + (z21 * z13));
      float c = (x3 * x3) + (y3 * y3) + (z3 * z3);
      c += (x1 * x1) + (y1 * y1) + (z1 * z1);
      c -= 2.0f * (x3 * x1 + y3 * y1 + z3 * z1);
      c -= r * r;

      // b^2 - 4ac
      float determ = b * b - 4.0f * a * c;

      // no hit
      if (determ < 0.0f)
         return false;

      // skip tangent hit (determ == 0.0)

      // intersection, 2 hits
      float inv_a2 = 0.5f / a;
      float sqrt_d = (float) Math.sqrt(determ);

      float u0 = (-b - sqrt_d) * inv_a2;
      if (u0 >= 0.0f && u0 <= 1.0f)
         return true;

      float u1 = (-b + sqrt_d) * inv_a2;
      if (u1 >= 0.0f && u1 <= 1.0f)
         return true;

      return false;
   }

   public static int lineHitsSphere(Vec3 p1, Vec3 p2, Vec3 p3, float r, float[] result)
   {
      float x1 = p1.x;
      float y1 = p1.y;
      float z1 = p1.z;

      float x2 = p2.x;
      float y2 = p2.y;
      float z2 = p2.z;

      float x3 = p3.x;
      float y3 = p3.y;
      float z3 = p3.z;

      // diff between line-points
      float x21 = x2 - x1;
      float y21 = y2 - y1;
      float z21 = z2 - z1;

      // diff between first line-point and sphere origin
      float x13 = x1 - x3;
      float y13 = y1 - y3;
      float z13 = z1 - z3;

      // y = ax^2 + bx + c
      float a = (x21 * x21) + (y21 * y21) + (z21 * z21);
      float b = 2.0f * ((x21 * x13) + (y21 * y13) + (z21 * z13));
      float c = (x3 * x3) + (y3 * y3) + (z3 * z3);
      c += (x1 * x1) + (y1 * y1) + (z1 * z1);
      c -= 2.0f * (x3 * x1 + y3 * y1 + z3 * z1);
      c -= r * r;

      // b^2 - 4ac
      float determ = b * b - 4.0f * a * c;

      // no hit
      if (determ < 0.0f)
         return 0;

      // tangent hit
      if (determ == 0.0f)
      {
         result[0] = -b / (2.0f * a);
         return 1;
      }

      // intersection, 2 hits
      float inv_a2 = 0.5f / a;
      float sqrt_d = (float) Math.sqrt(determ);
      result[0] = (-b - sqrt_d) * inv_a2;
      result[1] = (-b + sqrt_d) * inv_a2;

      return 2;
   }

   public static float linePathLengthThroughSphere(long v3a, long v3b, long v3s, float r)
   {
      float xA = fget(v3a + 0L);
      float yA = fget(v3a + 4L);
      float zA = fget(v3a + 8L);

      float xB = fget(v3b + 0L);
      float yB = fget(v3b + 4L);
      float zB = fget(v3b + 8L);

      float xS = fget(v3s + 0L);
      float yS = fget(v3s + 4L);
      float zS = fget(v3s + 8L);

      // offset B from A
      float xBA = xB - xA;
      float yBA = yB - yA;
      float zBA = zB - zA;

      float xAS = xA - xS;
      float yAS = yA - yS;
      float zAS = zA - zS;

      float a = (xBA * xBA) + (yBA * yBA) + (zBA * zBA);
      float b = 2.0f * ((xBA * xAS) + (yBA * yAS) + (zBA * zAS));
      float c = (xS * xS) + (yS * yS) + (zS * zS);
      c += (xA * xA) + (yA * yA) + (zA * zA);
      c -= ((xS * xA) + (yS * yA) + (zS * zA)) * 2.0f;
      c -= r * r;

      float determ = b * b - 4.0f * a * c;
      if (determ <= 0.0f)
         return 0.0f;

      float sqrt_d = (float) Math.sqrt(determ);
      float inv_a2 = 0.5f / a;
      float t0 = (-b - sqrt_d) * inv_a2;
      float t1 = (-b + sqrt_d) * inv_a2;

      // both out of bounds
      if ((t0 < 0.0f || t0 > 1.0f) && (t1 < 0.0f || t1 > 1.0f))
         return 0.0f;

      float x0 = xA + t0 * (xB - xA);
      float y0 = yA + t0 * (yB - yA);
      float z0 = zA + t0 * (zB - zA);

      float x1 = xA + t1 * (xB - xA);
      float y1 = yA + t1 * (yB - yA);
      float z1 = zA + t1 * (zB - zA);

      float x01 = x0 - x1;
      float y01 = y0 - y1;
      float z01 = z0 - z1;

      return (float) Math.sqrt(x01 * x01 + y01 * y01 + z01 * z01);
   }

   public static float linePathLengthThroughSphere(Vec3 p1, Vec3 p2, Vec3 p3, float r)
   {
      float[] result = new float[2];
      int intersections = lineHitsSphere(p1, p2, p3, r, result);
      if (intersections != 2)
         return 0.0f;

      Vec3 tA = VecMath.lerp(result[0], p1, p2);
      Vec3 tB = VecMath.lerp(result[1], p1, p2);
      return VecMath.distance(tA, tB);
   }

   public static boolean sphereIntersectsTriangle(Vec3 p, float r, Vec3 a, Vec3 b, Vec3 c, Vec3 aux)
   {
      if (true)
         throw new IllegalStateException();
      // ShapeMath3D.closestPointOnTriangle(p, a, b, c, aux);
      Vec3 closest = aux;
      Vec3 diff = new Vec3(closest).sub(p);

      float squaredDist = dot(diff, diff);
      float squaredRadius = r * r;

      return squaredDist < squaredRadius;
   }

   public static boolean pushSphereOutOfTriangle(Vec3 p, float r, Vec3 a, Vec3 b, Vec3 c, float factor, Vec3 aux)
   {
      if (true)
         throw new IllegalStateException();
      // closestPointOnTriangle(p, a, b, c, aux);
      Vec3 closest = aux;
      Vec3 diff = new Vec3(closest).sub(p);

      float squaredDist = dot(diff, diff);
      float squaredRadius = r * r;

      if (squaredDist >= squaredRadius)
         return false;

      float dist = (float) Math.sqrt(squaredDist);
      float intersection = r - dist;

      // push using [normal of triangle]
      // p.add(normal(a, b, c).mul(intersection * factor));

      // push using [normal of hit]
      p.add(diff.normalize().mul(intersection * factor));

      return true;
   }

   /**
    * TRIANGLE AREA
    */

   public static final float triangleArea(Vec3 p1, Vec3 p2, Vec3 p3)
   {
      float ab = distance(p1, p2);
      float bc = distance(p2, p3);
      float ca = distance(p3, p1);
      float s = (ab + bc + ca) * 0.5f;
      return (float) Math.sqrt(s * (s - ab) * (s - bc) * (s - ca));
   }
}
