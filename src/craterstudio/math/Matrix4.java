/*
 * Created on Sep 21, 2004
 */
package craterstudio.math;

import java.nio.FloatBuffer;
import java.util.NoSuchElementException;

import craterstudio.text.TextValues;

public class Matrix4 {
	private Matrix4[] stack;
	private int index;

	public void push() {
		if (stack == null) {
			stack = new Matrix4[4];
		}
		if (index == stack.length) {
			Matrix4[] tmp = new Matrix4[stack.length * 2];
			System.arraycopy(this.stack, 0, tmp, 0, stack.length);
			stack = tmp;
		}
		if (stack[index] == null) {
			stack[index] = new Matrix4();
		}
		stack[index++].set(this);
	}

	public void pop() {
		if (stack == null || index <= 0)
			throw new NoSuchElementException();
		this.set(stack[--index]);
	}

	/**
	 * MATRIX
	 */

	public float m00, m01, m02, m03;
	public float m10, m11, m12, m13;
	public float m20, m21, m22, m23;
	public float m30, m31, m32, m33;

	/**
	 * CONSTRUCTORS
	 */

	public Matrix4() {
		m00 = m11 = m22 = m33 = 1.0F;
	}

	public final Vec3 transform(Vec3 src_dst) {
		return this.transform(src_dst, src_dst);
	}

	public final Vec3 transform(Vec3 src, Vec3 dst) {
		float x = src.x;
		float y = src.y;
		float z = src.z;

		dst.x = m00 * x + m01 * y + m02 * z + m03;
		dst.y = m10 * x + m11 * y + m12 * z + m13;
		dst.z = m20 * x + m21 * y + m22 * z + m23;

		return dst;
	}

	public final Matrix4 identity() {
		m01 = m02 = m03 = 0.0f;
		m10 = m12 = m13 = 0.0f;
		m20 = m21 = m23 = 0.0f;
		m30 = m31 = m32 = 0.0f;
		m00 = m11 = m22 = m33 = 1.0f;
		return this;
	}

	public final Matrix4 scale(Vec3 v) {
		return this.scale(v.x, v.y, v.z);
	}

	public final Matrix4 scale(float x, float y, float z) {
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

	public final Matrix4 scale(float d) {
		return this.scale(d, d, d);
	}

	/**
	 * TRANSLATE
	 */

	public final Matrix4 translate(Vec3 v) {
		return this.translate(v.x, v.y, v.z);
	}

	public final Matrix4 translate(float x, float y, float z) {
		m03 += m00 * x + m01 * y + m02 * z;
		m13 += m10 * x + m11 * y + m12 * z;
		m23 += m20 * x + m21 * y + m22 * z;
		m33 += m30 * x + m31 * y + m32 * z;

		return this;
	}

	/**
	 * ROT
	 */

	private static float cosDeg(float a) {
		// return (float)Math.cos(Math.toRadians(a))
		return FastMath.cosDeg(a);
	}

	private static float sinDeg(float a) {
		// return (float)Math.sin(Math.toRadians(a))
		return FastMath.sinDeg(a);
	}

	public final Matrix4 rotX(float a) {
		float d11 = cosDeg(a);
		float d21 = sinDeg(a);
		float d12 = -d21;
		float d22 = d11;

		float t01 = m01 * d11 + m02 * d21;
		m02 = m01 * d12 + m02 * d22;
		float t11 = m11 * d11 + m12 * d21;
		m12 = m11 * d12 + m12 * d22;
		float t21 = m21 * d11 + m22 * d21;
		m22 = m21 * d12 + m22 * d22;
		float t31 = m31 * d11 + m32 * d21;
		m32 = m31 * d12 + m32 * d22;

		m01 = t01;
		m11 = t11;
		m21 = t21;
		m31 = t31;

		return this;
	}

	public final Matrix4 rotY(float a) {
		a = -a;

		float d00 = cosDeg(a);
		float d20 = sinDeg(a);
		float d02 = -d20;
		float d22 = d00;

		float t00 = m00 * d00 + m02 * d20;
		m02 = m00 * d02 + m02 * d22;
		float t10 = m10 * d00 + m12 * d20;
		m12 = m10 * d02 + m12 * d22;
		float t20 = m20 * d00 + m22 * d20;
		m22 = m20 * d02 + m22 * d22;
		float t30 = m30 * d00 + m32 * d20;
		m32 = m30 * d02 + m32 * d22;

		m00 = t00;
		m10 = t10;
		m20 = t20;
		m30 = t30;

		return this;
	}

	public final Matrix4 rotYRad(float a) {
		a = -a;

		float d00 = (float) Math.cos(a);
		float d20 = (float) Math.sin(a);
		float d02 = -d20;
		float d22 = d00;

		float t00 = m00 * d00 + m02 * d20;
		m02 = m00 * d02 + m02 * d22;
		float t10 = m10 * d00 + m12 * d20;
		m12 = m10 * d02 + m12 * d22;
		float t20 = m20 * d00 + m22 * d20;
		m22 = m20 * d02 + m22 * d22;
		float t30 = m30 * d00 + m32 * d20;
		m32 = m30 * d02 + m32 * d22;

		m00 = t00;
		m10 = t10;
		m20 = t20;
		m30 = t30;

		return this;
	}

	public final Matrix4 rotZ(float a) {
		float d00 = cosDeg(a);
		float d10 = sinDeg(a);
		float d01 = -d10;
		float d11 = d00;

		float t00 = m00 * d00 + m01 * d10;
		m01 = m00 * d01 + m01 * d11;
		float t10 = m10 * d00 + m11 * d10;
		m11 = m10 * d01 + m11 * d11;
		float t20 = m20 * d00 + m21 * d10;
		m21 = m20 * d01 + m21 * d11;
		float t30 = m30 * d00 + m31 * d10;
		m31 = m30 * d01 + m31 * d11;

		m00 = t00;
		m10 = t10;
		m20 = t20;
		m30 = t30;

		return this;
	}

	public final Matrix4 rotate(Vec3 rot) {
		return this.rotate(rot.x, rot.y, rot.z);
	}

	public final Matrix4 rotate(float x, float y, float z) {
		y = -y;

		float cx = cosDeg(x);
		float sx = sinDeg(x);
		float cy = cosDeg(y);
		float sy = sinDeg(y);
		float cz = cosDeg(z);
		float sz = sinDeg(z);

		float cxsy = cx * sy;
		float sxsy = sx * sy;

		//

		float d00 = +cy * cz;
		float d01 = -cy * sz;
		float d02 = -sy;

		float d10 = -sxsy * cz + cx * sz;
		float d11 = +sxsy * sz + cx * cz;
		float d12 = -sx * cy;

		float d20 = +cxsy * cz + sx * sz;
		float d21 = -cxsy * sz + sx * cz;
		float d22 = +cx * cy;

		//

		float t00 = m00 * d00 + m01 * d10 + m02 * d20;
		float t01 = m00 * d01 + m01 * d11 + m02 * d21;
		float t02 = m00 * d02 + m01 * d12 + m02 * d22;

		float t10 = m10 * d00 + m11 * d10 + m12 * d20;
		float t11 = m10 * d01 + m11 * d11 + m12 * d21;
		float t12 = m10 * d02 + m11 * d12 + m12 * d22;

		float t20 = m20 * d00 + m21 * d10 + m22 * d20;
		float t21 = m20 * d01 + m21 * d11 + m22 * d21;
		float t22 = m20 * d02 + m21 * d12 + m22 * d22;

		float t30 = m30 * d00 + m31 * d10 + m32 * d20;
		float t31 = m30 * d01 + m31 * d11 + m32 * d21;
		float t32 = m30 * d02 + m31 * d12 + m32 * d22;

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

	public final Matrix4 mult(Matrix4 m) {
		float t00 = m00 * m.m00 + m01 * m.m10 + m02 * m.m20 + m03 * m.m30;
		float t01 = m00 * m.m01 + m01 * m.m11 + m02 * m.m21 + m03 * m.m31;
		float t02 = m00 * m.m02 + m01 * m.m12 + m02 * m.m22 + m03 * m.m32;
		float t03 = m00 * m.m03 + m01 * m.m13 + m02 * m.m23 + m03 * m.m33;

		float t10 = m10 * m.m00 + m11 * m.m10 + m12 * m.m20 + m13 * m.m30;
		float t11 = m10 * m.m01 + m11 * m.m11 + m12 * m.m21 + m13 * m.m31;
		float t12 = m10 * m.m02 + m11 * m.m12 + m12 * m.m22 + m13 * m.m32;
		float t13 = m10 * m.m03 + m11 * m.m13 + m12 * m.m23 + m13 * m.m33;

		float t20 = m20 * m.m00 + m21 * m.m10 + m22 * m.m20 + m23 * m.m30;
		float t21 = m20 * m.m01 + m21 * m.m11 + m22 * m.m21 + m23 * m.m31;
		float t22 = m20 * m.m02 + m21 * m.m12 + m22 * m.m22 + m23 * m.m32;
		float t23 = m20 * m.m03 + m21 * m.m13 + m22 * m.m23 + m23 * m.m33;

		float t30 = m30 * m.m00 + m31 * m.m10 + m32 * m.m20 + m33 * m.m30;
		float t31 = m30 * m.m01 + m31 * m.m11 + m32 * m.m21 + m33 * m.m31;
		float t32 = m30 * m.m02 + m31 * m.m12 + m32 * m.m22 + m33 * m.m32;
		float t33 = m30 * m.m03 + m31 * m.m13 + m32 * m.m23 + m33 * m.m33;

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
	 * PROCESS
	 */

	public final Vec3 fillOrigin(Vec3 vec) {
		vec.x = m03;
		vec.y = m13;
		vec.z = m23;

		return vec;
	}

	public final Vec3 transformOrientation(Vec3 src_dst) {
		return this.transformOrientation(src_dst, src_dst);
	}

	public final Vec3 transformOrientation(Vec3 src, Vec3 dst) {
		float x = src.x;
		float y = src.y;
		float z = src.z;

		dst.x = m00 * x + m01 * y + m02 * z;
		dst.y = m10 * x + m11 * y + m12 * z;
		dst.z = m20 * x + m21 * y + m22 * z;

		return dst;
	}

	/**
	 * TRANSLATION
	 */

	public final void getTranslation(Vec3 translation) {
		translation.load(m03, m13, m23);
	}

	/**
	 * COLUMN
	 */

	public final void setTranslate(Vec3 v) {
		m03 = v.x;
		m13 = v.y;
		m23 = v.z;
	}

	public final void setRow(int row, Vec4 v) {
		switch (row) {
			case 0:
				m00 = v.x;
				m01 = v.y;
				m02 = v.z;
				m03 = v.w;
				break;
			case 1:
				m10 = v.x;
				m11 = v.y;
				m12 = v.z;
				m13 = v.w;
				break;
			case 2:
				m20 = v.x;
				m21 = v.y;
				m22 = v.z;
				m23 = v.w;
				break;
			case 3:
				m30 = v.x;
				m31 = v.y;
				m32 = v.z;
				m33 = v.w;
				break;
		}
	}

	/**
	 * GET / SET
	 */

	public final void get(FloatBuffer dst) {
		dst.put(0, m00);
		dst.put(1, m01);
		dst.put(2, m02);
		dst.put(3, m03);

		dst.put(4, m10);
		dst.put(5, m11);
		dst.put(6, m12);
		dst.put(7, m13);

		dst.put(8, m20);
		dst.put(9, m21);
		dst.put(10, m22);
		dst.put(11, m23);

		dst.put(12, m30);
		dst.put(13, m31);
		dst.put(14, m32);
		dst.put(15, m33);
	}

	public final void get(Matrix4 dst) {
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

	public final void set(Matrix4 src) {
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

	public final void set(FloatBuffer src) {
		m00 = src.get(0);
		m01 = src.get(1);
		m02 = src.get(2);
		m03 = src.get(3);

		m10 = src.get(4);
		m11 = src.get(5);
		m12 = src.get(6);
		m13 = src.get(7);

		m20 = src.get(8);
		m21 = src.get(9);
		m22 = src.get(10);
		m23 = src.get(11);

		m30 = src.get(12);
		m31 = src.get(13);
		m32 = src.get(14);
		m33 = src.get(15);
	}

	/**
	 * GET / SET TRANSPOSE
	 */

	public final void getTranspose(FloatBuffer dst) {
		dst.put(0, m00);
		dst.put(1, m10);
		dst.put(2, m20);
		dst.put(3, m30);

		dst.put(4, m01);
		dst.put(5, m11);
		dst.put(6, m21);
		dst.put(7, m31);

		dst.put(8, m02);
		dst.put(9, m12);
		dst.put(10, m22);
		dst.put(11, m32);

		dst.put(12, m03);
		dst.put(13, m13);
		dst.put(14, m23);
		dst.put(15, m33);
	}

	public final void setTranspose(FloatBuffer src) {
		m00 = src.get(0);
		m10 = src.get(1);
		m20 = src.get(2);
		m30 = src.get(3);

		m01 = src.get(4);
		m11 = src.get(5);
		m21 = src.get(6);
		m31 = src.get(7);

		m02 = src.get(8);
		m12 = src.get(9);
		m22 = src.get(10);
		m32 = src.get(11);

		m03 = src.get(12);
		m13 = src.get(13);
		m23 = src.get(14);
		m33 = src.get(15);
	}

	/**
	 * INVERT
	 */

	public final Matrix4 invert() {
		float determinant = determinant();

		if (determinant == 0.0F) {
			return this;
		}

		// first row
		float t00 = +determinant3x3(m11, m12, m13, m21, m22, m23, m31, m32, m33);
		float t01 = -determinant3x3(m10, m12, m13, m20, m22, m23, m30, m32, m33);
		float t02 = +determinant3x3(m10, m11, m13, m20, m21, m23, m30, m31, m33);
		float t03 = -determinant3x3(m10, m11, m12, m20, m21, m22, m30, m31, m32);
		// second row
		float t10 = -determinant3x3(m01, m02, m03, m21, m22, m23, m31, m32, m33);
		float t11 = +determinant3x3(m00, m02, m03, m20, m22, m23, m30, m32, m33);
		float t12 = -determinant3x3(m00, m01, m03, m20, m21, m23, m30, m31, m33);
		float t13 = +determinant3x3(m00, m01, m02, m20, m21, m22, m30, m31, m32);
		// third row
		float t20 = +determinant3x3(m01, m02, m03, m11, m12, m13, m31, m32, m33);
		float t21 = -determinant3x3(m00, m02, m03, m10, m12, m13, m30, m32, m33);
		float t22 = +determinant3x3(m00, m01, m03, m10, m11, m13, m30, m31, m33);
		float t23 = -determinant3x3(m00, m01, m02, m10, m11, m12, m30, m31, m32);
		// fourth row
		float t30 = -determinant3x3(m01, m02, m03, m11, m12, m13, m21, m22, m23);
		float t31 = +determinant3x3(m00, m02, m03, m10, m12, m13, m20, m22, m23);
		float t32 = -determinant3x3(m00, m01, m03, m10, m11, m13, m20, m21, m23);
		float t33 = +determinant3x3(m00, m01, m02, m10, m11, m12, m20, m21, m22);

		// transpose and divide by the determinant
		float invDeterminant = 1.0f / determinant;
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

	private final float determinant() {
		float f = 0.0f;
		f += m00 * ((m11 * m22 * m33 + m12 * m23 * m31 + m13 * m21 * m32) - (m13 * m22 * m31 + m11 * m23 * m32 + m12 * m21 * m33));
		f -= m01 * ((m10 * m22 * m33 + m12 * m23 * m30 + m13 * m20 * m32) - (m13 * m22 * m30 + m10 * m23 * m32 + m12 * m20 * m33));
		f += m02 * ((m10 * m21 * m33 + m11 * m23 * m30 + m13 * m20 * m31) - (m13 * m21 * m30 + m10 * m23 * m31 + m11 * m20 * m33));
		f -= m03 * ((m10 * m21 * m32 + m11 * m22 * m30 + m12 * m20 * m31) - (m12 * m21 * m30 + m10 * m22 * m31 + m11 * m20 * m32));
		return f;
	}

	private final float determinant3x3(float t00, float t01, float t02, float t10, float t11, float t12, float t20, float t21, float t22) {
		return t00 * (t11 * t22 - t12 * t21) + t01 * (t12 * t20 - t10 * t22) + t02 * (t10 * t21 - t11 * t20);
	}

	/**
	 * EQUALS
	 */

	public final boolean equals(Matrix4 mat, float margin) {
		if (!(EasyMath.equals(m00, mat.m00, margin) && EasyMath.equals(m10, mat.m10, margin) && EasyMath.equals(m20, mat.m20, margin) && EasyMath.equals(m30, mat.m30, margin)))
			return false;
		if (!(EasyMath.equals(m01, mat.m01, margin) && EasyMath.equals(m11, mat.m11, margin) && EasyMath.equals(m21, mat.m21, margin) && EasyMath.equals(m31, mat.m31, margin)))
			return false;
		if (!(EasyMath.equals(m02, mat.m02, margin) && EasyMath.equals(m12, mat.m12, margin) && EasyMath.equals(m22, mat.m22, margin) && EasyMath.equals(m32, mat.m32, margin)))
			return false;
		return EasyMath.equals(m03, mat.m03, margin) && EasyMath.equals(m13, mat.m13, margin) && EasyMath.equals(m23, mat.m23, margin) && EasyMath.equals(m33, mat.m33, margin);
	}

	public final float cumulativeDiff(Matrix4 m) {
		float sum = 0.0f;

		sum += Math.abs(m00 - m.m00);
		sum += Math.abs(m01 - m.m01);
		sum += Math.abs(m02 - m.m02);
		sum += Math.abs(m03 - m.m03);

		sum += Math.abs(m10 - m.m10);
		sum += Math.abs(m11 - m.m11);
		sum += Math.abs(m12 - m.m12);
		sum += Math.abs(m13 - m.m13);

		sum += Math.abs(m20 - m.m20);
		sum += Math.abs(m21 - m.m21);
		sum += Math.abs(m22 - m.m22);
		sum += Math.abs(m23 - m.m23);

		sum += Math.abs(m30 - m.m30);
		sum += Math.abs(m31 - m.m31);
		sum += Math.abs(m32 - m.m32);
		sum += Math.abs(m33 - m.m33);

		return sum;
	}

	/**
	 * TO STRING
	 */

	public final String toString() {
		StringBuffer buffer = new StringBuffer();

		String sep = "  ";

		buffer.append("Matrix4[ ");
		buffer.append(TextValues.formatNumber(m00, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m01, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m02, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m03, 3, 3) + "\n");

		buffer.append("         ");
		buffer.append(TextValues.formatNumber(m10, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m11, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m12, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m13, 3, 3) + "\n");

		buffer.append("         ");
		buffer.append(TextValues.formatNumber(m20, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m21, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m22, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m23, 3, 3) + "\n");

		buffer.append("         ");
		buffer.append(TextValues.formatNumber(m30, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m31, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m32, 3, 3) + sep);
		buffer.append(TextValues.formatNumber(m33, 3, 3) + " ]");

		return buffer.toString();
	}
}