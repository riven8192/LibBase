/*
 * Created on 23 apr 2010
 */

package craterstudio.math;

public class RawIntersectionMath
{
   public static boolean intersectsPlaneSphere(float px, float py, float pz, float pd, float sx, float sy, float sz, float srad)
   {
      float x = px * (sx - px * pd);
      float y = py * (sy - py * pd);
      float z = pz * (sz - pz * pd);
      float sd = x + y + z;
      return (sd < 0.0f) ? (-sd < srad) : (sd < srad);
   }

   public static boolean intersectsSphereRay(float sox, float soy, float soz, float srad, float rox, float roy, float roz, float rnx, float rny, float rnz)
   {
      float dfx = rox - sox;
      float dfy = roy - soy;
      float dfz = roz - soz;
      float B = (dfx * rnx) + (dfy * rny) + (dfz * rnz);
      float C = (dfx * dfx) + (dfy * dfy) + (dfz * dfz) - (srad * srad);
      return (B * B - C) >= 0.0f;
   }

   public static float intersectionSphereRay(float sox, float soy, float soz, float srad, float rox, float roy, float roz, float rnx, float rny, float rnz)
   {
      float dfx = rox - sox;
      float dfy = roy - soy;
      float dfz = roz - soz;
      float B = (dfx * rnx) + (dfy * rny) + (dfz * rnz);
      float C = (dfx * dfx) + (dfy * dfy) + (dfz * dfz) - (srad * srad);
      float D = B * B - C;
      return (D >= 0.0f) ? (-B - (float) Math.sqrt(D)) : Float.POSITIVE_INFINITY;
   }

   public static float intersectionLengthSphereRay(float sox, float soy, float soz, float srad, float rox, float roy, float roz, float rnx, float rny, float rnz)
   {
      float dfx = rox - sox;
      float dfy = roy - soy;
      float dfz = roz - soz;
      float B = (dfx * rnx) + (dfy * rny) + (dfz * rnz);
      float C = (dfx * dfx) + (dfy * dfy) + (dfz * dfz) - (srad * srad);

      float D = B * B - C;
      if (D <= 0.0f)
         return 0.0f;
      return 2.0f * (float) Math.sqrt(D);
   }

   public static float intersectionPlaneRay(float px, float py, float pz, float pd, float rox, float roy, float roz, float rnx, float rny, float rnz)
   {
      float dot1x = px - (px * pd) + rox;
      float dot1y = py - (py * pd) + roy;
      float dot1z = pz - (pz * pd) + roz;

      float dot2x = px - rnx;
      float dot2y = py - rny;
      float dot2z = pz - rnz;

      float dot1 = dot1x * dot1x + dot1y * dot1y + dot1z * dot1z;
      float dot2 = dot2x * dot2x + dot2y * dot2y + dot2z * dot2z;

      return dot1 / dot2;
   }

   public static void fillRayPosition(float rox, float roy, float roz, float rnx, float rny, float rnz, float t, float[] result)
   {
      result[0] = rox + rnx * t;
      result[1] = roy + rny * t;
      result[2] = roz + rnz * t;
   }
}