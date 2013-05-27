package craterstudio.math;

public class Rotation {
	private float cos, sin;

	public Rotation() {
		cos = 1.0f;
		sin = 0.0f;
	}

	//

	public static Rotation fromVector(Vec2 vector) {
		return new Rotation().setFromVector(vector);
	}

	public static Rotation fromDegrees(float degrees) {
		return new Rotation().setFromDegrees(degrees);
	}

	public static Rotation fromRadians(float degrees) {
		return new Rotation().setFromRadians(degrees);
	}

	//

	public Rotation setFromVector(Vec2 vector) {
		cos = vector.x;
		sin = vector.y;
		return this.renormalize();
	}

	public Rotation setFromDegrees(float degrees) {
		cos = FastMath.cosDeg(degrees);
		sin = FastMath.sinDeg(degrees);
		return this;
	}

	public Rotation setFromRadians(float radians) {
		cos = FastMath.cos(radians);
		sin = FastMath.sin(radians);
		return this;
	}

	//

	public Rotation add(Rotation that) {
		float x1 = this.cos, y1 = that.cos;
		float x2 = this.sin, y2 = that.sin;
		this.cos = x1 * x2 - y1 * y2;
		this.sin = y2 * x2 + x1 * y2;
		return this;
	}

	public Rotation renormalize() {
		float len = (float) Math.sqrt(cos * cos + sin * sin);
		cos /= len;
		sin /= len;
		return this;
	}

	//

	public Vec2 rotate(Vec2 vec) {
		return this.rotate(vec, vec);
	}

	public Vec2 rotate(Vec2 src, Vec2 dst) {
		float x = src.x, y = src.y;
		dst.x = cos * x - sin * y;
		dst.y = sin * x + cos * y;
		return dst;
	}

	//

	public void rotateAroundX(Vec3 src, Vec3 dst) {
		float y = src.y, z = src.z;
		dst.x = src.x;
		dst.y = cos * y - sin * z;
		dst.z = sin * y + cos * z;
	}

	public void rotateAroundY(Vec3 src, Vec3 dst) {
		float x = src.x, z = src.z;
		dst.x = cos * x - sin * z;
		dst.y = src.y;
		dst.z = sin * x + cos * z;
	}

	public void rotateAroundZ(Vec3 src, Vec3 dst) {
		float x = src.x, y = src.y;
		dst.x = cos * x - sin * y;
		dst.y = sin * x + cos * y;
		dst.z = src.z;
	}

	public void rotateAroundX(Vec3 src, Vec3 origin, Vec3 dst) {
		float y = src.y - origin.y, z = src.z - origin.z;
		dst.x = src.x;
		dst.y = cos * y - sin * z + origin.y;
		dst.z = sin * y + cos * z + origin.z;
	}

	public void rotateAroundY(Vec3 src, Vec3 origin, Vec3 dst) {
		float x = src.x - origin.x, z = src.z - origin.z;
		dst.x = cos * x - sin * z + origin.x;
		dst.y = src.y;
		dst.z = sin * x + cos * z + origin.z;
	}

	public void rotateAroundZ(Vec3 src, Vec3 origin, Vec3 dst) {
		float x = src.x - origin.x, y = src.y - origin.y;
		dst.x = cos * x - sin * y + origin.x;
		dst.y = sin * x + cos * y + origin.y;
		dst.z = src.z;
	}
}
