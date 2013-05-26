package craterstudio.math;

import craterstudio.text.TextValues;

public class Matrix3
{
   /**
    * MATRIX
    */

   public float m00, m01, m02;
   public float m10, m11, m12;
   public float m20, m21, m22;

   public Matrix3()
   {
      this.m00 = this.m11 = this.m22 = 1.0f;
   }

   /**
    * PROCESS
    */

   public final Vec2 process(Vec2 src, Vec2 dst)
   {
      float x = src.x;
      float y = src.y;

      dst.x = x * m00 + y * m01 + m02;
      dst.y = x * m10 + y * m11 + m12;

      return dst;
   }

   /**
    * IDENTITY
    */

   public final void identity()
   {
      m01 = m02 = 0.0f;
      m10 = m12 = 0.0f;
      m20 = m21 = 0.0f;
      m00 = m11 = m22 = 1.0f;
   }

   /**
    * TRANSPOSE
    */

   public final void transpose()
   {
      float t01 = m10;
      float t02 = m20;

      float t10 = m01;
      float t12 = m21;

      float t20 = m02;
      float t21 = m12;

      //

      m01 = t01;
      m02 = t02;

      m10 = t10;
      m12 = t12;

      m20 = t20;
      m21 = t21;
   }

   /**
    * SCALE
    */

   public final void scale(Vec2 v)
   {
      this.scale(v.x, v.y);
   }

   public final void scale(float x, float y)
   {
      m00 *= x;
      m10 *= x;
      m20 *= x;

      m01 *= y;
      m11 *= y;
      m21 *= y;
   }

   public final void scaleX(float s)
   {
      m00 *= s;
      m10 *= s;
      m20 *= s;
   }

   public final void scaleY(float s)
   {
      m01 *= s;
      m11 *= s;
      m21 *= s;
   }

   public final void scale(float d)
   {
      m00 *= d;
      m10 *= d;
      m20 *= d;

      m01 *= d;
      m11 *= d;
      m21 *= d;
   }

   /**
    * TRANSLATE
    */

   public final void translate(Vec2 v)
   {
      this.translate(v.x, v.y);
   }

   public final void translate(float x, float y)
   {
      m02 += m00 * x + m01 * y;
      m12 += m10 * x + m11 * y;
      m22 += m20 * x + m21 * y;
   }

   public final void translateX(float t)
   {
      m02 += m00 * t;
      m12 += m10 * t;
      m22 += m20 * t;
   }

   public final void translateY(float t)
   {
      m02 += m01 * t;
      m12 += m11 * t;
      m22 += m21 * t;
   }

   /**
    * ROTATE
    */

   public final void rot(float a)
   {
      if (true)
         throw new UnsupportedOperationException("bugged");
      a = -a;

      float d00 = FastMath.cosDeg(a);
      float d20 = FastMath.sinDeg(a);
      float d02 = -d20;
      float d22 = d00;

      float t00 = m00 * d00 + m02 * d20;
      m02 = m00 * d02 + m02 * d22;
      float t10 = m10 * d00 + m12 * d20;
      m12 = m10 * d02 + m12 * d22;
      float t20 = m20 * d00 + m22 * d20;
      m22 = m20 * d02 + m22 * d22;

      m00 = t00;
      m10 = t10;
      m20 = t20;
   }

   /**
    * MULT
    */

   public final void mult(Matrix3 m)
   {
      float t00 = m00 * m.m00 + m01 * m.m10 + m02 * m.m20;
      float t01 = m00 * m.m01 + m01 * m.m11 + m02 * m.m21;
      float t02 = m00 * m.m02 + m01 * m.m12 + m02 * m.m22;

      float t10 = m10 * m.m00 + m11 * m.m10 + m12 * m.m20;
      float t11 = m10 * m.m01 + m11 * m.m11 + m12 * m.m21;
      float t12 = m10 * m.m02 + m11 * m.m12 + m12 * m.m22;

      float t20 = m20 * m.m00 + m21 * m.m10 + m22 * m.m20;
      float t21 = m20 * m.m01 + m21 * m.m11 + m22 * m.m21;
      float t22 = m20 * m.m02 + m21 * m.m12 + m22 * m.m22;

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
   }

   /**
    * EQUALS
    */

   public final boolean equals(Matrix4 mat, float margin)
   {
      if (!(EasyMath.equals(m00, mat.m00, margin) && EasyMath.equals(m10, mat.m10, margin) && EasyMath.equals(m20, mat.m20, margin)))
         return false;
      if (!(EasyMath.equals(m01, mat.m01, margin) && EasyMath.equals(m11, mat.m11, margin) && EasyMath.equals(m21, mat.m21, margin)))
         return false;
      return EasyMath.equals(m02, mat.m02, margin) && EasyMath.equals(m12, mat.m12, margin) && EasyMath.equals(m22, mat.m22, margin);
   }

   public final float cumulativeDiff(Matrix4 m)
   {
      float sum = 0.0f;

      sum += Math.abs(m00 - m.m00);
      sum += Math.abs(m01 - m.m01);
      sum += Math.abs(m02 - m.m02);

      sum += Math.abs(m10 - m.m10);
      sum += Math.abs(m11 - m.m11);
      sum += Math.abs(m12 - m.m12);

      sum += Math.abs(m20 - m.m20);
      sum += Math.abs(m21 - m.m21);
      sum += Math.abs(m22 - m.m22);

      return sum;
   }

   /**
    * TO STRING
    */

   public final String toString()
   {
      StringBuffer buffer = new StringBuffer();

      String sep = "  ";

      buffer.append("Matrix3[ ");
      buffer.append(TextValues.formatNumber(m00, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m01, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m02, 3, 3) + "\n");

      buffer.append("         ");
      buffer.append(TextValues.formatNumber(m10, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m11, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m12, 3, 3) + "\n");

      buffer.append("         ");
      buffer.append(TextValues.formatNumber(m20, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m21, 3, 3) + sep);
      buffer.append(TextValues.formatNumber(m22, 3, 3) + "\n");

      return buffer.toString();
   }
}
