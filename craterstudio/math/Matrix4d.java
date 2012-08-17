/*
 * Created on Sep 21, 2004
 */
package craterstudio.math;

import java.nio.DoubleBuffer;
import java.util.LinkedList;
import java.util.NoSuchElementException;

import craterstudio.text.TextValues;

public class Matrix4d
{
   private LinkedList<Matrix4d> stack;

   public void push()
   {
      if (stack == null)
         stack = new LinkedList<Matrix4d>();
      Matrix4d copy = new Matrix4d();
      copy.set(this);
      stack.push(copy);
   }

   public void pop()
   {
      if (stack == null || stack.isEmpty())
         throw new NoSuchElementException();
      this.set(stack.pop());
   }

   /**
    * MATRIX
    */

   public double m00, m01, m02, m03;
   public double m10, m11, m12, m13;
   public double m20, m21, m22, m23;
   public double m30, m31, m32, m33;

   /**
    * CONSTRUCTORS
    */

   public Matrix4d()
   {
      m00 = m11 = m22 = m33 = 1.0F;
   }

   /**
    * PROCESS
    */

   public final Vec3 fillOrigin(Vec3 vec)
   {
      vec.x = (float) m03;
      vec.y = (float) m13;
      vec.z = (float) m23;

      return vec;
   }

   public final Vec3 transform(Vec3 src_dst)
   {
      return this.transform(src_dst, src_dst);
   }

   public final Vec3 transform(Vec3 src, Vec3 dst)
   {
      double x = src.x;
      double y = src.y;
      double z = src.z;

      dst.x = (float) (m00 * x + m01 * y + m02 * z + m03);
      dst.y = (float) (m10 * x + m11 * y + m12 * z + m13);
      dst.z = (float) (m20 * x + m21 * y + m22 * z + m23);

      return dst;
   }

   /**
    * GET / SET
    */

   public final void get(DoubleBuffer dst)
   {
      int pos = dst.position();

      dst.put(pos + 0, m00);
      dst.put(pos + 1, m01);
      dst.put(pos + 2, m02);
      dst.put(pos + 3, m03);

      dst.put(pos + 4, m10);
      dst.put(pos + 5, m11);
      dst.put(pos + 6, m12);
      dst.put(pos + 7, m13);

      dst.put(pos + 8, m20);
      dst.put(pos + 9, m21);
      dst.put(pos + 10, m22);
      dst.put(pos + 11, m23);

      dst.put(pos + 12, m30);
      dst.put(pos + 13, m31);
      dst.put(pos + 14, m32);
      dst.put(pos + 15, m33);

      dst.position(pos + 16);
   }

   public final void get(Matrix4d dst)
   {
      dst.m00 = m00;
      dst.m01 = m01;
      dst.m02 = m02;
      dst.m03 = m03;

      dst.m10 = m10;
      dst.m11 = m11;
      dst.m12 = m12;
      dst.m13 = m13;

      dst.m20 = m20;
      dst.m21 = m21;
      dst.m22 = m22;
      dst.m23 = m23;

      dst.m30 = m30;
      dst.m31 = m31;
      dst.m32 = m32;
      dst.m33 = m33;
   }

   public final void set(Matrix4d src)
   {
      m00 = src.m00;
      m01 = src.m01;
      m02 = src.m02;
      m03 = src.m03;

      m10 = src.m10;
      m11 = src.m11;
      m12 = src.m12;
      m13 = src.m13;

      m20 = src.m20;
      m21 = src.m21;
      m22 = src.m22;
      m23 = src.m23;

      m30 = src.m30;
      m31 = src.m31;
      m32 = src.m32;
      m33 = src.m33;
   }

   public final void set(DoubleBuffer src)
   {
      int pos = src.position();

      m00 = src.get(pos + 0);
      m01 = src.get(pos + 1);
      m02 = src.get(pos + 2);
      m03 = src.get(pos + 3);

      m10 = src.get(pos + 4);
      m11 = src.get(pos + 5);
      m12 = src.get(pos + 6);
      m13 = src.get(pos + 7);

      m20 = src.get(pos + 8);
      m21 = src.get(pos + 9);
      m22 = src.get(pos + 10);
      m23 = src.get(pos + 11);

      m30 = src.get(pos + 12);
      m31 = src.get(pos + 13);
      m32 = src.get(pos + 14);
      m33 = src.get(pos + 15);

      src.position(pos + 16);
   }




   /**
    * IDENTITY
    */

   public final Matrix4d identity()
   {
      m01 = m02 = m03 = 0.0;
      m10 = m12 = m13 = 0.0;
      m20 = m21 = m23 = 0.0;
      m30 = m31 = m32 = 0.0;
      m00 = m11 = m22 = m33 = 1.0;
      return this;
   }

   /**
    * TRANSPOSE
    */

   public final Matrix4d transpose()
   {
      double t01 = m10;
      double t02 = m20;
      double t03 = m30;

      double t10 = m01;
      double t12 = m21;
      double t13 = m31;

      double t20 = m02;
      double t21 = m12;
      double t23 = m32;

      double t30 = m03;
      double t31 = m13;
      double t32 = m23;

      //

      m01 = t01;
      m02 = t02;
      m03 = t03;

      m10 = t10;
      m12 = t12;
      m13 = t13;

      m20 = t20;
      m21 = t21;
      m23 = t23;

      m30 = t30;
      m31 = t31;
      m32 = t32;

      return this;
   }

   /**
    * INVERT
    */

   public final Matrix4d invert()
   {
      double determinant = determinant();

      if (determinant == 0.0F)
      {
         return this;
      }

      // first row
      double t00 = +determinant3x3(m11, m12, m13, m21, m22, m23, m31, m32, m33);
      double t01 = -determinant3x3(m10, m12, m13, m20, m22, m23, m30, m32, m33);
      double t02 = +determinant3x3(m10, m11, m13, m20, m21, m23, m30, m31, m33);
      double t03 = -determinant3x3(m10, m11, m12, m20, m21, m22, m30, m31, m32);
      // second row
      double t10 = -determinant3x3(m01, m02, m03, m21, m22, m23, m31, m32, m33);
      double t11 = +determinant3x3(m00, m02, m03, m20, m22, m23, m30, m32, m33);
      double t12 = -determinant3x3(m00, m01, m03, m20, m21, m23, m30, m31, m33);
      double t13 = +determinant3x3(m00, m01, m02, m20, m21, m22, m30, m31, m32);
      // third row
      double t20 = +determinant3x3(m01, m02, m03, m11, m12, m13, m31, m32, m33);
      double t21 = -determinant3x3(m00, m02, m03, m10, m12, m13, m30, m32, m33);
      double t22 = +determinant3x3(m00, m01, m03, m10, m11, m13, m30, m31, m33);
      double t23 = -determinant3x3(m00, m01, m02, m10, m11, m12, m30, m31, m32);
      // fourth row
      double t30 = -determinant3x3(m01, m02, m03, m11, m12, m13, m21, m22, m23);
      double t31 = +determinant3x3(m00, m02, m03, m10, m12, m13, m20, m22, m23);
      double t32 = -determinant3x3(m00, m01, m03, m10, m11, m13, m20, m21, m23);
      double t33 = +determinant3x3(m00, m01, m02, m10, m11, m12, m20, m21, m22);

      // transpose and divide by the determinant
      double invDeterminant = 1.0 / determinant;
      m00 = t00 * invDeterminant;
      m01 = t10 * invDeterminant;
      m02 = t20 * invDeterminant;
      m03 = t30 * invDeterminant;
      m10 = t01 * invDeterminant;
      m11 = t11 * invDeterminant;
      m12 = t21 * invDeterminant;
      m13 = t31 * invDeterminant;
      m20 = t02 * invDeterminant;
      m21 = t12 * invDeterminant;
      m22 = t22 * invDeterminant;
      m23 = t32 * invDeterminant;
      m30 = t03 * invDeterminant;
      m31 = t13 * invDeterminant;
      m32 = t23 * invDeterminant;
      m33 = t33 * invDeterminant;

      return this;
   }

   private final double determinant()
   {
      double f = 0.0f;
      f += m00 * ((m11 * m22 * m33 + m12 * m23 * m31 + m13 * m21 * m32) - (m13 * m22 * m31 + m11 * m23 * m32 + m12 * m21 * m33));
      f -= m01 * ((m10 * m22 * m33 + m12 * m23 * m30 + m13 * m20 * m32) - (m13 * m22 * m30 + m10 * m23 * m32 + m12 * m20 * m33));
      f += m02 * ((m10 * m21 * m33 + m11 * m23 * m30 + m13 * m20 * m31) - (m13 * m21 * m30 + m10 * m23 * m31 + m11 * m20 * m33));
      f -= m03 * ((m10 * m21 * m32 + m11 * m22 * m30 + m12 * m20 * m31) - (m12 * m21 * m30 + m10 * m22 * m31 + m11 * m20 * m32));
      return f;
   }

   private final double determinant3x3(double t00, double t01, double t02, double t10, double t11, double t12, double t20, double t21, double t22)
   {
      return t00 * (t11 * t22 - t12 * t21) + t01 * (t12 * t20 - t10 * t22) + t02 * (t10 * t21 - t11 * t20);
   }

   /**
    * SCALE
    */

   public final Matrix4d scale(Vec3 v)
   {
      return this.scale(v.x, v.y, v.z);
   }

   public final Matrix4d scale(double x, double y, double z)
   {
      m00 *= x;
      m10 *= x;
      m20 *= x;
      m30 *= x;

      m01 *= y;
      m11 *= y;
      m21 *= y;
      m31 *= y;

      m02 *= z;
      m12 *= z;
      m22 *= z;
      m32 *= z;

      return this;
   }

   public final Matrix4d scaleX(double s)
   {
      m00 *= s;
      m10 *= s;
      m20 *= s;
      m30 *= s;

      return this;
   }

   public final Matrix4d scaleY(double s)
   {
      m01 *= s;
      m11 *= s;
      m21 *= s;
      m31 *= s;

      return this;
   }

   public final Matrix4d scaleZ(double s)
   {
      m02 *= s;
      m12 *= s;
      m22 *= s;
      m32 *= s;

      return this;
   }

   public final Matrix4d scale(double d)
   {
      m00 *= d;
      m10 *= d;
      m20 *= d;
      m30 *= d;

      m01 *= d;
      m11 *= d;
      m21 *= d;
      m31 *= d;

      m02 *= d;
      m12 *= d;
      m22 *= d;
      m32 *= d;

      return this;
   }

   /**
    * TRANSLATE
    */

   public final Matrix4d translate(Vec3 v)
   {
      return this.translate(v.x, v.y, v.z);
   }

   public final Matrix4d translate(double x, double y, double z)
   {
      m03 += m00 * x + m01 * y + m02 * z;
      m13 += m10 * x + m11 * y + m12 * z;
      m23 += m20 * x + m21 * y + m22 * z;
      m33 += m30 * x + m31 * y + m32 * z;

      return this;
   }

   public final Matrix4d translateX(double t)
   {
      m03 += m00 * t;
      m13 += m10 * t;
      m23 += m20 * t;
      m33 += m30 * t;

      return this;
   }

   public final Matrix4d translateY(double t)
   {
      m03 += m01 * t;
      m13 += m11 * t;
      m23 += m21 * t;
      m33 += m31 * t;

      return this;
   }

   public final Matrix4d translateZ(double t)
   {
      m03 += m02 * t;
      m13 += m12 * t;
      m23 += m22 * t;
      m33 += m32 * t;

      return this;
   }

   /**
    * ROT
    */

   private static final double cosDeg(double deg)
   {
      return Math.cos(Math.toRadians(deg));
   }

   private static final double sinDeg(double deg)
   {
      return Math.sin(Math.toRadians(deg));
   }

   public final Matrix4d rotX(double a)
   {
      double d11 = Matrix4d.cosDeg(a);
      double d21 = Matrix4d.sinDeg(a);
      double d12 = -d21;
      double d22 = d11;

      double t01 = m01 * d11 + m02 * d21;
      m02 = m01 * d12 + m02 * d22;
      double t11 = m11 * d11 + m12 * d21;
      m12 = m11 * d12 + m12 * d22;
      double t21 = m21 * d11 + m22 * d21;
      m22 = m21 * d12 + m22 * d22;
      double t31 = m31 * d11 + m32 * d21;
      m32 = m31 * d12 + m32 * d22;

      m01 = t01;
      m11 = t11;
      m21 = t21;
      m31 = t31;

      return this;
   }

   public final Matrix4d rotY(double a)
   {
      a = -a;

      double d00 = Matrix4d.cosDeg(a);
      double d20 = Matrix4d.sinDeg(a);
      double d02 = -d20;
      double d22 = d00;

      double t00 = m00 * d00 + m02 * d20;
      m02 = m00 * d02 + m02 * d22;
      double t10 = m10 * d00 + m12 * d20;
      m12 = m10 * d02 + m12 * d22;
      double t20 = m20 * d00 + m22 * d20;
      m22 = m20 * d02 + m22 * d22;
      double t30 = m30 * d00 + m32 * d20;
      m32 = m30 * d02 + m32 * d22;

      m00 = t00;
      m10 = t10;
      m20 = t20;
      m30 = t30;

      return this;
   }

   public final Matrix4d rotZ(double a)
   {
      double d00 = Matrix4d.cosDeg(a);
      double d10 = Matrix4d.sinDeg(a);
      double d01 = -d10;
      double d11 = d00;

      double t00 = m00 * d00 + m01 * d10;
      m01 = m00 * d01 + m01 * d11;
      double t10 = m10 * d00 + m11 * d10;
      m11 = m10 * d01 + m11 * d11;
      double t20 = m20 * d00 + m21 * d10;
      m21 = m20 * d01 + m21 * d11;
      double t30 = m30 * d00 + m31 * d10;
      m31 = m30 * d01 + m31 * d11;

      m00 = t00;
      m10 = t10;
      m20 = t20;
      m30 = t30;

      return this;
   }

   public final Matrix4d rotate(Vec3 rot)
   {
      return this.rotate(rot.x, rot.y, rot.z);
   }

   public final Matrix4d rotate(double x, double y, double z)
   {
      y = -y;

      double cx = Matrix4d.cosDeg(x);
      double sx = Matrix4d.sinDeg(x);
      double cy = Matrix4d.cosDeg(y);
      double sy = Matrix4d.sinDeg(y);
      double cz = Matrix4d.cosDeg(z);
      double sz = Matrix4d.sinDeg(z);

      double cxsy = cx * sy;
      double sxsy = sx * sy;

      //

      double d00 = +cy * +cz;
      double d01 = -cy * +sz;
      double d02 = -sy;

      double d10 = -sxsy * cz + cx * sz;
      double d11 = +sxsy * sz + cx * cz;
      double d12 = -sx * +cy;

      double d20 = +cxsy * cz + sx * sz;
      double d21 = -cxsy * sz + sx * cz;
      double d22 = +cx * +cy;

      //

      double t00 = m00 * d00 + m01 * d10 + m02 * d20;
      double t01 = m00 * d01 + m01 * d11 + m02 * d21;
      double t02 = m00 * d02 + m01 * d12 + m02 * d22;

      double t10 = m10 * d00 + m11 * d10 + m12 * d20;
      double t11 = m10 * d01 + m11 * d11 + m12 * d21;
      double t12 = m10 * d02 + m11 * d12 + m12 * d22;

      double t20 = m20 * d00 + m21 * d10 + m22 * d20;
      double t21 = m20 * d01 + m21 * d11 + m22 * d21;
      double t22 = m20 * d02 + m21 * d12 + m22 * d22;

      double t30 = m30 * d00 + m31 * d10 + m32 * d20;
      double t31 = m30 * d01 + m31 * d11 + m32 * d21;
      double t32 = m30 * d02 + m31 * d12 + m32 * d22;

      //

      m00 = t00;
      m01 = t01;
      m02 = t02;

      m10 = t10;
      m11 = t11;
      m12 = t12;

      m20 = t20;
      m21 = t21;
      m22 = t22;

      m30 = t30;
      m31 = t31;
      m32 = t32;

      return this;
   }

   /**
    * MULT
    */

   public final Matrix4d mult(Matrix4d m)
   {
      double t00 = m00 * m.m00 + m01 * m.m10 + m02 * m.m20 + m03 * m.m30;
      double t01 = m00 * m.m01 + m01 * m.m11 + m02 * m.m21 + m03 * m.m31;
      double t02 = m00 * m.m02 + m01 * m.m12 + m02 * m.m22 + m03 * m.m32;
      double t03 = m00 * m.m03 + m01 * m.m13 + m02 * m.m23 + m03 * m.m33;

      double t10 = m10 * m.m00 + m11 * m.m10 + m12 * m.m20 + m13 * m.m30;
      double t11 = m10 * m.m01 + m11 * m.m11 + m12 * m.m21 + m13 * m.m31;
      double t12 = m10 * m.m02 + m11 * m.m12 + m12 * m.m22 + m13 * m.m32;
      double t13 = m10 * m.m03 + m11 * m.m13 + m12 * m.m23 + m13 * m.m33;

      double t20 = m20 * m.m00 + m21 * m.m10 + m22 * m.m20 + m23 * m.m30;
      double t21 = m20 * m.m01 + m21 * m.m11 + m22 * m.m21 + m23 * m.m31;
      double t22 = m20 * m.m02 + m21 * m.m12 + m22 * m.m22 + m23 * m.m32;
      double t23 = m20 * m.m03 + m21 * m.m13 + m22 * m.m23 + m23 * m.m33;

      double t30 = m30 * m.m00 + m31 * m.m10 + m32 * m.m20 + m33 * m.m30;
      double t31 = m30 * m.m01 + m31 * m.m11 + m32 * m.m21 + m33 * m.m31;
      double t32 = m30 * m.m02 + m31 * m.m12 + m32 * m.m22 + m33 * m.m32;
      double t33 = m30 * m.m03 + m31 * m.m13 + m32 * m.m23 + m33 * m.m33;

      //

      m00 = t00;
      m01 = t01;
      m02 = t02;
      m03 = t03;

      m10 = t10;
      m11 = t11;
      m12 = t12;
      m13 = t13;

      m20 = t20;
      m21 = t21;
      m22 = t22;
      m23 = t23;

      m30 = t30;
      m31 = t31;
      m32 = t32;
      m33 = t33;

      return this;
   }

   /**
    * TO STRING
    */

   public final String toString()
   {
      StringBuffer buffer = new StringBuffer();

      String sep = "  ";

      buffer.append("Matrix4d[ ");
      buffer.append(TextValues.formatNumber(m00, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m01, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m02, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m03, 3, 3) + "\n");

      buffer.append("          ");
      buffer.append(TextValues.formatNumber(m10, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m11, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m12, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m13, 3, 3) + "\n");

      buffer.append("          ");
      buffer.append(TextValues.formatNumber(m20, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m21, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m22, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m23, 3, 3) + "\n");

      buffer.append("          ");
      buffer.append(TextValues.formatNumber(m30, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m31, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m32, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m33, 3, 3) + " ]");

      return buffer.toString();
   }
}