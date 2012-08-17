/*
 * Created on 8 jul 2008
 */

package craterstudio.math;

import craterstudio.text.TextValues;

public class Mat4 {
	public final float[] arr;

	public Mat4() {
		this.arr = new float[16];
	}

	public Mat4(float[] mat) {
		if (mat.length != 16)
			throw new IllegalArgumentException();
		this.arr = mat;
	}

	public Mat4(Mat4 mat) {
		this();
		Mat4.duplicate(mat.arr, this.arr);
	}

	public void identity() {
		Mat4.identity(arr);
	}

	public void identityKeepTranslation() {
		Mat4.identityKeepTranslation(arr);
	}

	public void transformOne(float[] vector) {
		Mat4.transformOne(arr, vector);
	}

	public void transformOne(float[] vector, int offset) {
		Mat4.transformOne(arr, vector, offset);
	}

	public void transform(float[] vectors, int offset, int stride) {
		Mat4.transform(arr, vectors, offset, stride);
	}

	public void transform(float[] vectors, int offset, int stride, int elements) {
		Mat4.transform(arr, vectors, offset, stride, elements);
	}

	public void transpose() {
		float[] tmp = new float[16];
		Mat4.transpose(arr, tmp);
		Mat4.duplicate(tmp, arr);
	}

	public void scale(float x, float y, float z) {
		Mat4.scale(arr, x, y, z);
	}

	public void translate(float x, float y, float z) {
		Mat4.translate(arr, x, y, z);
	}

	public void rotX(float angle) {
		Mat4.rotX(arr, angle);
	}

	public void rotY(float angle) {
		Mat4.rotY(arr, angle);
	}

	public void rotZ(float angle) {
		Mat4.rotZ(arr, angle);
	}

	public void rotXrad(float angle) {
		Mat4.rotXrad(arr, angle);
	}

	public void rotYrad(float angle) {
		Mat4.rotYrad(arr, angle);
	}

	public void rotZrad(float angle) {
		Mat4.rotZrad(arr, angle);
	}

	public void concatenate(Mat4 mat) {
		Mat4.concatenate(this.arr, mat.arr);
	}

	public void invert() {
		float[] tmp = new float[16];
		Mat4.invert(arr, tmp);
		Mat4.duplicate(tmp, arr);
	}

	public String toString() {
		return Mat4.toString(arr);
	}

	//
	// static
	//

	public static void identity(float[] mat) {
		mat[m00] = 1;
		mat[m01] = 0;
		mat[m02] = 0;
		mat[m03] = 0;
		mat[m10] = 0;
		mat[m11] = 1;
		mat[m12] = 0;
		mat[m13] = 0;
		mat[m20] = 0;
		mat[m21] = 0;
		mat[m22] = 1;
		mat[m23] = 0;
		mat[m30] = 0;
		mat[m31] = 0;
		mat[m32] = 0;
		mat[m33] = 1;
	}

	public static void identityKeepTranslation(float[] mat) {
		mat[m00] = 1;
		mat[m01] = 0;
		mat[m02] = 0;
		// mat[m03] = 0;
		mat[m10] = 0;
		mat[m11] = 1;
		mat[m12] = 0;
		// mat[m13] = 0;
		mat[m20] = 0;
		mat[m21] = 0;
		mat[m22] = 1;
		// mat[m23] = 0;
		mat[m30] = 0;
		mat[m31] = 0;
		mat[m32] = 0;
		mat[m33] = 1;
	}

	public static float[] duplicate(float[] src, float[] dst) {
		System.arraycopy(src, 0, dst, 0, 16);

		return dst;
	}

	public static void transformOne(float[] matrix, float[] vector) {
		transformOne(matrix, vector, 0);
	}

	public static void transformOne(float[] matrix, float[] vector, int offset) {
		float x = vector[offset + 0];
		float y = vector[offset + 1];
		float z = vector[offset + 2];

		vector[offset + 0] = matrix[m00] * x + matrix[m01] * y + matrix[m02] * z + matrix[m03];
		vector[offset + 1] = matrix[m10] * x + matrix[m11] * y + matrix[m12] * z + matrix[m13];
		vector[offset + 2] = matrix[m20] * x + matrix[m21] * y + matrix[m22] * z + matrix[m23];
	}

	public static void transform(float[] matrix, float[] vectors, int offset, int stride) {
		transform(matrix, vectors, offset, stride, (vectors.length - offset) / stride);
	}

	public static void transform(float[] matrix, float[] vectors, int offset, int stride, int elements) {
		float x, y, z;

		int end = offset + stride * elements;

		for (int i = offset; i < end; i += stride) {
			x = vectors[i + 0];
			y = vectors[i + 1];
			z = vectors[i + 2];

			vectors[i + 0] = matrix[m00] * x + matrix[m01] * y + matrix[m02] * z + matrix[m03];
			vectors[i + 1] = matrix[m10] * x + matrix[m11] * y + matrix[m12] * z + matrix[m13];
			vectors[i + 2] = matrix[m20] * x + matrix[m21] * y + matrix[m22] * z + matrix[m23];
		}
	}

	//

	public static void transpose(float[] src, float[] dst) {
		dst[m00] = src[m00];
		dst[m10] = src[m01];
		dst[m20] = src[m02];
		dst[m30] = src[m03];

		dst[m01] = src[m10];
		dst[m11] = src[m11];
		dst[m21] = src[m12];
		dst[m31] = src[m13];

		dst[m02] = src[m20];
		dst[m12] = src[m21];
		dst[m22] = src[m22];
		dst[m32] = src[m23];

		dst[m03] = src[m30];
		dst[m13] = src[m31];
		dst[m23] = src[m32];
		dst[m33] = src[m33];
	}

	public static void scale(float[] mat, float x, float y, float z) {
		mat[m00] *= x;
		mat[m01] *= y;
		mat[m02] *= z;

		mat[m10] *= x;
		mat[m11] *= y;
		mat[m12] *= z;

		mat[m20] *= x;
		mat[m21] *= y;
		mat[m22] *= z;

		mat[m30] *= x;
		mat[m31] *= y;
		mat[m32] *= z;
	}

	public static void translate(float[] mat, float x, float y, float z) {
		mat[m03] += mat[m00] * x + mat[m01] * y + mat[m02] * z;
		mat[m13] += mat[m10] * x + mat[m11] * y + mat[m12] * z;
		mat[m23] += mat[m20] * x + mat[m21] * y + mat[m22] * z;
		mat[m33] += mat[m30] * x + mat[m31] * y + mat[m32] * z;
	}

	//

	public static void rotX(float[] mat, float angle) {
		rotXrad(mat, (float) Math.toRadians(angle));
	}

	public static void rotY(float[] mat, float angle) {
		rotYrad(mat, (float) Math.toRadians(angle));
	}

	public static void rotZ(float[] mat, float angle) {
		rotZrad(mat, (float) Math.toRadians(angle));
	}

	//

	public static void rotXrad(float[] mat, float angle) {
		float d11 = (float) Math.cos(angle);
		float d21 = (float) Math.sin(angle);
		float d12 = -d21;
		float d22 = d11;

		float t0 = mat[m01] * d11 + mat[m02] * d21;
		mat[m02] = mat[m01] * d12 + mat[m02] * d22;
		float t1 = mat[m11] * d11 + mat[m12] * d21;
		mat[m12] = mat[m11] * d12 + mat[m12] * d22;
		float t2 = mat[m21] * d11 + mat[m22] * d21;
		mat[m22] = mat[m21] * d12 + mat[m22] * d22;
		float t3 = mat[m31] * d11 + mat[m32] * d21;
		mat[m32] = mat[m31] * d12 + mat[m32] * d22;

		mat[m01] = t0;
		mat[m11] = t1;
		mat[m21] = t2;
		mat[m31] = t3;
	}

	public static void rotYrad(float[] mat, float angle) {
		angle = -angle;

		float d00 = (float) Math.cos(angle);
		float d20 = (float) Math.sin(angle);
		float d02 = -d20;
		float d22 = d00;

		float t0 = mat[m00] * d00 + mat[m02] * d20;
		mat[m02] = mat[m00] * d02 + mat[m02] * d22;
		float t1 = mat[m10] * d00 + mat[m12] * d20;
		mat[m12] = mat[m10] * d02 + mat[m12] * d22;
		float t2 = mat[m20] * d00 + mat[m22] * d20;
		mat[m22] = mat[m20] * d02 + mat[m22] * d22;
		float t3 = mat[m30] * d00 + mat[m32] * d20;
		mat[m32] = mat[m30] * d02 + mat[m32] * d22;

		mat[m00] = t0;
		mat[m10] = t1;
		mat[m20] = t2;
		mat[m30] = t3;
	}

	public static void rotZrad(float[] mat, float angle) {
		float d00 = (float) Math.cos(angle);
		float d10 = (float) Math.sin(angle);
		float d01 = -d10;
		float d11 = d00;

		float t0 = mat[m00] * d00 + mat[m01] * d10;
		mat[m01] = mat[m00] * d01 + mat[m01] * d11;
		float t1 = mat[m10] * d00 + mat[m11] * d10;
		mat[m11] = mat[m10] * d01 + mat[m11] * d11;
		float t2 = mat[m20] * d00 + mat[m21] * d10;
		mat[m21] = mat[m20] * d01 + mat[m21] * d11;
		float t3 = mat[m30] * d00 + mat[m31] * d10;
		mat[m31] = mat[m30] * d01 + mat[m31] * d11;

		mat[m00] = t0;
		mat[m10] = t1;
		mat[m20] = t2;
		mat[m30] = t3;
	}

	//

	public static float[] concatenate(float[] op1, float[] op2, float[] res) {
		res[m00] = op1[m00] * op2[m00] + op1[m01] * op2[m10] + op1[m02] * op2[m20] + op1[m03] * op2[m30];
		res[m01] = op1[m00] * op2[m01] + op1[m01] * op2[m11] + op1[m02] * op2[m21] + op1[m03] * op2[m31];
		res[m02] = op1[m00] * op2[m02] + op1[m01] * op2[m12] + op1[m02] * op2[m22] + op1[m03] * op2[m32];
		res[m03] = op1[m00] * op2[m03] + op1[m01] * op2[m13] + op1[m02] * op2[m23] + op1[m03] * op2[m33];

		res[m10] = op1[m10] * op2[m00] + op1[m11] * op2[m10] + op1[m12] * op2[m20] + op1[m13] * op2[m30];
		res[m11] = op1[m10] * op2[m01] + op1[m11] * op2[m11] + op1[m12] * op2[m21] + op1[m13] * op2[m31];
		res[m12] = op1[m10] * op2[m02] + op1[m11] * op2[m12] + op1[m12] * op2[m22] + op1[m13] * op2[m32];
		res[m13] = op1[m10] * op2[m03] + op1[m11] * op2[m13] + op1[m12] * op2[m23] + op1[m13] * op2[m33];

		res[m20] = op1[m20] * op2[m00] + op1[m21] * op2[m10] + op1[m22] * op2[m20] + op1[m23] * op2[m30];
		res[m21] = op1[m20] * op2[m01] + op1[m21] * op2[m11] + op1[m22] * op2[m21] + op1[m23] * op2[m31];
		res[m22] = op1[m20] * op2[m02] + op1[m21] * op2[m12] + op1[m22] * op2[m22] + op1[m23] * op2[m32];
		res[m23] = op1[m20] * op2[m03] + op1[m21] * op2[m13] + op1[m22] * op2[m23] + op1[m23] * op2[m33];

		res[m30] = op1[m30] * op2[m00] + op1[m31] * op2[m10] + op1[m32] * op2[m20] + op1[m33] * op2[m30];
		res[m31] = op1[m30] * op2[m01] + op1[m31] * op2[m11] + op1[m32] * op2[m21] + op1[m33] * op2[m31];
		res[m32] = op1[m30] * op2[m02] + op1[m31] * op2[m12] + op1[m32] * op2[m22] + op1[m33] * op2[m32];
		res[m33] = op1[m30] * op2[m03] + op1[m31] * op2[m13] + op1[m32] * op2[m23] + op1[m33] * op2[m33];

		return res;
	}

	public static float[] concatenate(float[] mat, float[] val) {
		float t00 = mat[m00] * val[m00] + mat[m01] * val[m10] + mat[m02] * val[m20] + mat[m03] * val[m30];
		float t01 = mat[m00] * val[m01] + mat[m01] * val[m11] + mat[m02] * val[m21] + mat[m03] * val[m31];
		float t02 = mat[m00] * val[m02] + mat[m01] * val[m12] + mat[m02] * val[m22] + mat[m03] * val[m32];
		float t03 = mat[m00] * val[m03] + mat[m01] * val[m13] + mat[m02] * val[m23] + mat[m03] * val[m33];

		float t10 = mat[m10] * val[m00] + mat[m11] * val[m10] + mat[m12] * val[m20] + mat[m13] * val[m30];
		float t11 = mat[m10] * val[m01] + mat[m11] * val[m11] + mat[m12] * val[m21] + mat[m13] * val[m31];
		float t12 = mat[m10] * val[m02] + mat[m11] * val[m12] + mat[m12] * val[m22] + mat[m13] * val[m32];
		float t13 = mat[m10] * val[m03] + mat[m11] * val[m13] + mat[m12] * val[m23] + mat[m13] * val[m33];

		float t20 = mat[m20] * val[m00] + mat[m21] * val[m10] + mat[m22] * val[m20] + mat[m23] * val[m30];
		float t21 = mat[m20] * val[m01] + mat[m21] * val[m11] + mat[m22] * val[m21] + mat[m23] * val[m31];
		float t22 = mat[m20] * val[m02] + mat[m21] * val[m12] + mat[m22] * val[m22] + mat[m23] * val[m32];
		float t23 = mat[m20] * val[m03] + mat[m21] * val[m13] + mat[m22] * val[m23] + mat[m23] * val[m33];

		float t30 = mat[m30] * val[m00] + mat[m31] * val[m10] + mat[m32] * val[m20] + mat[m33] * val[m30];
		float t31 = mat[m30] * val[m01] + mat[m31] * val[m11] + mat[m32] * val[m21] + mat[m33] * val[m31];
		float t32 = mat[m30] * val[m02] + mat[m31] * val[m12] + mat[m32] * val[m22] + mat[m33] * val[m32];
		float t33 = mat[m30] * val[m03] + mat[m31] * val[m13] + mat[m32] * val[m23] + mat[m33] * val[m33];

		//

		mat[m00] = t00;
		mat[m01] = t01;
		mat[m02] = t02;
		mat[m03] = t03;

		mat[m10] = t10;
		mat[m11] = t11;
		mat[m12] = t12;
		mat[m13] = t13;

		mat[m20] = t20;
		mat[m21] = t21;
		mat[m22] = t22;
		mat[m23] = t23;

		mat[m30] = t30;
		mat[m31] = t31;
		mat[m32] = t32;
		mat[m33] = t33;

		return mat;
	}

	public static final void fillTranslation(float[] mat, float[] translation) {
		translation[0] = mat[X_TRANSLATION];
		translation[1] = mat[Y_TRANSLATION];
		translation[2] = mat[Z_TRANSLATION];
	}

	public static final void lookAt(float[] mat, float nx, float ny, float nz) {
		Mat4.identityKeepTranslation(mat);
		Mat4.rotYrad(mat, (float) Math.atan2(nx, nz));
		Mat4.rotXrad(mat, (float) Math.asin(-ny));
	}

	public static final void lookAt(float[] mat, float[] target) {
		float nx = target[0];
		float ny = target[1];
		float nz = target[2];
		float d = (float) Math.sqrt(nx * nx + ny * ny + nz * nz);
		nx /= d;
		ny /= d;
		nz /= d;

		Mat4.identityKeepTranslation(mat);
		Mat4.rotYrad(mat, (float) Math.atan2(nx, nz));
		Mat4.rotXrad(mat, (float) Math.asin(-ny));
	}

	public static final void lookAt(float[] mat, float[] eye, float[] target, boolean gotoEye) {
		float nx = eye[0] - target[0];
		float ny = eye[1] - target[1];
		float nz = eye[2] - target[2];
		float d = (float) Math.sqrt(nx * nx + ny * ny + nz * nz);
		nx /= d;
		ny /= d;
		nz /= d;

		if (gotoEye) {
			Mat4.identity(mat);
			Mat4.translate(mat, eye[0], eye[1], eye[2]);
		} else {
			Mat4.identityKeepTranslation(mat);
		}

		Mat4.rotYrad(mat, (float) Math.atan2(nx, nz));
		Mat4.rotXrad(mat, (float) Math.asin(-ny));
	}

	public static final void eulerToMatrix(float[] mat, float[] euler) {
		float cx = (float) Math.cos(euler[0]);
		float sx = (float) Math.sin(euler[0]);
		float cy = (float) Math.cos(euler[1]);
		float sy = (float) Math.sin(euler[1]);
		float cz = (float) Math.cos(euler[2]);
		float sz = (float) Math.sin(euler[2]);

		float cxsy = cx * sy;
		float sxsy = sx * sy;

		mat[m00] = cy * cz;
		mat[m01] = -cy * sz;
		mat[m02] = -sy;

		mat[m10] = -sxsy * cz + cx * sz;
		mat[m11] = +sxsy * sz + cx * cz;
		mat[m12] = -sx * cy;

		mat[m20] = +cxsy * cz + sx * sz;
		mat[m21] = -cxsy * sz + sx * cz;
		mat[m22] = cx * cy;

		mat[m03] = mat[m13] = mat[m23] = 0.0f;
		mat[m30] = mat[m31] = mat[m32] = 0.0f;
		mat[m33] = 1.0f;
	}

	public static final void matrixToEuler(float[] mat, float[] euler) {
		euler[1] = (float) -Math.asin(mat[m02]);

		float cy = (float) Math.cos(euler[1]);
		if (Math.abs(cy) > 0.005f) {
			euler[0] = (float) Math.atan2(-mat[m12], mat[m22]);
			euler[2] = (float) Math.atan2(-mat[m01], mat[m00]);
		} else {
			euler[0] = 0.0F;
			euler[2] = (float) Math.atan2(mat[m10], mat[m11]);
		}
	}

	public static final String toString(float[] mat) {
		int bf = 3;
		int af = 3;

		String s = "";
		s += TextValues.formatNumber(mat[m00], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m01], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m02], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m03], bf, af) + "\n";
		s += TextValues.formatNumber(mat[m10], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m11], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m12], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m13], bf, af) + "\n";
		s += TextValues.formatNumber(mat[m20], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m21], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m22], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m23], bf, af) + "\n";
		s += TextValues.formatNumber(mat[m30], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m31], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m32], bf, af) + ", ";
		s += TextValues.formatNumber(mat[m33], bf, af) + "\n";

		return s;
	}

	public static final void invert(float[] mat, float[] dst) {
		double[][] src = new double[4][4];
		for (int i = 0; i < 16; i++)
			src[i % 4][i / 4] = mat[i];

		double[][] res = Inverter.invert(src);
		for (int i = 0; i < 16; i++)
			dst[i] = (float) res[i % 4][i / 4];
	}

	private static class Inverter {
		public static double[][] invert(double[][] a) {
			int n = a.length;
			double x[][] = new double[n][n];
			double b[][] = new double[n][n];
			int index[] = new int[n];
			for (int i = 0; i < n; ++i)
				b[i][i] = 1;

			Inverter.gaussian(a, index);

			for (int i = 0; i < n - 1; ++i)
				for (int j = i + 1; j < n; ++j)
					for (int k = 0; k < n; ++k)
						b[index[j]][k] -= a[index[j]][i] * b[index[i]][k];

			for (int i = 0; i < n; ++i) {
				x[n - 1][i] = b[index[n - 1]][i] / a[index[n - 1]][n - 1];
				for (int j = n - 2; j >= 0; --j) {
					x[j][i] = b[index[j]][i];
					for (int k = j + 1; k < n; ++k)
						x[j][i] -= a[index[j]][k] * x[k][i];
					x[j][i] /= a[index[j]][j];
				}
			}
			return x;
		}

		public static void gaussian(double[][] a, int[] index) {
			int n = index.length;
			double c[] = new double[n];
			double pj;

			for (int i = 0; i < n; ++i)
				index[i] = i;

			for (int i = 0; i < n; ++i) {
				double c0, c1 = 0;
				for (int j = 0; j < n; ++j)
					if ((c0 = Math.abs(a[i][j])) > c1)
						c1 = c0;
				c[i] = c1;
			}

			int k = 0;
			for (int j = 0; j < n - 1; ++j) {
				double pi0, pi1 = 0;
				for (int i = j; i < n; ++i) {
					if ((pi0 = Math.abs(a[index[i]][j]) / c[index[i]]) > pi1) {
						pi1 = pi0;
						k = i;
					}
				}

				int itmp = index[j];
				index[j] = index[k];
				index[k] = itmp;
				for (int i = j + 1; i < n; ++i) {
					pj = a[index[i]][j] = a[index[i]][j] / a[index[j]][j];
					for (int l = j + 1; l < n; ++l)
						a[index[i]][l] -= pj * a[index[j]][l];
				}
			}
		}
	}

	public static final float PI = (float) Math.PI;
	public static final float HALF_PI = PI * 0.5f;
	public static final float TWO_PI = PI * 2.0f;

	public static final int m00, m01, m02, m03;
	public static final int m10, m11, m12, m13;
	public static final int m20, m21, m22, m23;
	public static final int m30, m31, m32, m33;

	static {
		boolean transposeInRAM = true;

		if (transposeInRAM) {
			m00 = 0;
			m01 = 4;
			m02 = 8;
			m03 = 12;

			m10 = 1;
			m11 = 5;
			m12 = 9;
			m13 = 13;

			m20 = 2;
			m21 = 6;
			m22 = 10;
			m23 = 14;

			m30 = 3;
			m31 = 7;
			m32 = 11;
			m33 = 15;
		} else {
			m00 = 0;
			m01 = 1;
			m02 = 2;
			m03 = 3;

			m10 = 4;
			m11 = 5;
			m12 = 6;
			m13 = 7;

			m20 = 8;
			m21 = 9;
			m22 = 10;
			m23 = 11;

			m30 = 12;
			m31 = 13;
			m32 = 14;
			m33 = 15;
		}
	}

	public static final int X_SCALE_ON_X = m00;
	public static final int X_SCALE_ON_Y = m01;
	public static final int X_SCALE_ON_Z = m02;
	public static final int X_TRANSLATION = m03;

	public static final int Y_SCALE_ON_X = m10;
	public static final int Y_SCALE_ON_Y = m11;
	public static final int Y_SCALE_ON_Z = m12;
	public static final int Y_TRANSLATION = m13;

	public static final int Z_SCALE_ON_X = m20;
	public static final int Z_SCALE_ON_Y = m21;
	public static final int Z_SCALE_ON_Z = m22;
	public static final int Z_TRANSLATION = m23;

}