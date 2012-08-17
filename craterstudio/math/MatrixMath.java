/*
 * Created on Aug 12, 2005
 */

package craterstudio.math;


public class MatrixMath
{
   /**
    * MATRIX <---> EULER
    */

   public static final void eulerToMatrix(Vec3 euler, Matrix4 mat)
   {
      float cx = FastMath.cosDeg(euler.x);
      float sx = FastMath.sinDeg(euler.x);
      float cy = FastMath.cosDeg(euler.y);
      float sy = FastMath.sinDeg(euler.y);
      float cz = FastMath.cosDeg(euler.z);
      float sz = FastMath.sinDeg(euler.z);

      float cxsy = cx * sy;
      float sxsy = sx * sy;

      mat.m00 = cy * cz;
      mat.m01 = -cy * sz;
      mat.m02 = -sy;

      mat.m10 = -sxsy * cz + cx * sz;
      mat.m11 = +sxsy * sz + cx * cz;
      mat.m12 = -sx * cy;

      mat.m20 = +cxsy * cz + sx * sz;
      mat.m21 = -cxsy * sz + sx * cz;
      mat.m22 = cx * cy;

      mat.m03 = mat.m13 = mat.m23 = mat.m30 = mat.m31 = mat.m32 = 0.0F;
      mat.m33 = 1.0F;
   }

   public static final void matrixToEuler(Matrix4 mat, Vec3 euler)
   {
      float y = -(float) Math.asin(mat.m02);
      float cy = FastMath.cos(y);

      euler.y = (float) Math.toDegrees(y);

      if (Math.abs(cy) > 0.005F)
      {
         euler.x = FastMath.atan2Deg(-mat.m12, mat.m22);
         euler.z = FastMath.atan2Deg(-mat.m01, mat.m00);
      }
      else
      {
         euler.x = 0.0F;
         euler.z = FastMath.atan2Deg(mat.m10, mat.m11);
      }
   }

   /**
    * LERP
    */

   private static final Vec3 aTra = new Vec3(), aRot = new Vec3();
   private static final Vec3 bTra = new Vec3(), bRot = new Vec3();
   private static final Vec3 rTra = new Vec3(), rRot = new Vec3();

   public static final void lerp(float t, Matrix4 a, Matrix4 b, Matrix4 r)
   {
      // retrieve translation and rotation
      a.getTranslation(aTra);
      b.getTranslation(bTra);

      MatrixMath.matrixToEuler(a, aRot);
      MatrixMath.matrixToEuler(b, bRot);

      // smallest distances between angles
      if (false)
      {
         aRot.x = EasyMath.moduloInRange(aRot.x, 0.0F, 360.0F);
         aRot.y = EasyMath.moduloInRange(aRot.y, 0.0F, 360.0F);
         aRot.z = EasyMath.moduloInRange(aRot.z, 0.0F, 360.0F);
         bRot.x = EasyMath.moduloInRange(bRot.x, 0.0F, 360.0F);
         bRot.y = EasyMath.moduloInRange(bRot.y, 0.0F, 360.0F);
         bRot.z = EasyMath.moduloInRange(bRot.z, 0.0F, 360.0F);

         float xDiff = aRot.x - bRot.x;
         float yDiff = aRot.y - bRot.y;
         float zDiff = aRot.z - bRot.z;

         if (xDiff > 180.0F)
            aRot.x -= 360.0F;
         else if (xDiff < -180.0F)
            bRot.x -= 360.0F;

         if (yDiff > 180.0F)
            aRot.y -= 360.0F;
         else if (yDiff < -180.0F)
            bRot.y -= 360.0F;

         if (zDiff > 180.0F)
            aRot.z -= 360.0F;
         else if (zDiff < -180.0F)
            bRot.z -= 360.0F;
      }

      // lerp translation and rotation
      VecMath.lerp(t, aTra, bTra, rTra);
      VecMath.lerp(t, aRot, bRot, rRot);

      // apply lerped data to matrix
      r.identity();
      r.translate(rTra);
      r.rotate(rRot);
   }

   /**
    * AXIS-ANGLE ---> MATRIX
    */

   private static final Vec3 axis = new Vec3();

   public static final void axisAngleToMatrix(Vec4 axisAngle, Matrix4 mat)
   {
      float rcos = FastMath.cosDegStrict(axisAngle.w);
      float rsin = FastMath.sinDegStrict(axisAngle.w);
      float one_minus_rcos = 1.0F - rcos;

      axis.load(axisAngle.x, axisAngle.y, axisAngle.z);
      axis.normalize();

      float u = axis.x;
      float v = axis.y;
      float w = axis.z;

      mat.m00 = +1 * rcos + u * u * one_minus_rcos;
      mat.m10 = +w * rsin + v * u * one_minus_rcos;
      mat.m20 = -v * rsin + w * u * one_minus_rcos;
      mat.m30 = 0.0F;
      mat.m01 = -w * rsin + u * v * one_minus_rcos;
      mat.m11 = +1 * rcos + v * v * one_minus_rcos;
      mat.m21 = +u * rsin + w * v * one_minus_rcos;
      mat.m31 = 0.0F;
      mat.m02 = +v * rsin + u * w * one_minus_rcos;
      mat.m12 = -u * rsin + v * w * one_minus_rcos;
      mat.m22 = +1 * rcos + w * w * one_minus_rcos;
      mat.m32 = 0.0F;

      mat.m33 = 1.0F;
   }
}