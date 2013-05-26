/*
 * Created on 10-okt-2004
 */
package craterstudio.math;

public class VecMath {
	public static Vec2 add(Vec2 a, Vec2 b) {
		return new Vec2().load(a).add(b);
	}

	public static Vec2 sub(Vec2 a, Vec2 b) {
		return new Vec2().load(a).sub(b);
	}

	public static Vec2 mul(Vec2 a, Vec2 b) {
		return new Vec2().load(a).mul(b);
	}

	public static Vec2 div(Vec2 a, Vec2 b) {
		return new Vec2().load(a).div(b);
	}

	//

	public static Vec3 add(Vec3 a, Vec3 b) {
		return new Vec3().load(a).add(b);
	}

	public static Vec3 sub(Vec3 a, Vec3 b) {
		return new Vec3().load(a).sub(b);
	}

	public static Vec3 mul(Vec3 a, Vec3 b) {
		return new Vec3().load(a).mul(b);
	}

	public static Vec3 div(Vec3 a, Vec3 b) {
		return new Vec3().load(a).div(b);
	}

	//

	/**
	 * MIN / MAX
	 */

	public static final Vec3 min(Vec3 vector, Vec3 compare) {
		if (compare.x < vector.x)
			vector.x = (compare.x);
		if (compare.y < vector.y)
			vector.y = (compare.y);
		if (compare.z < vector.z)
			vector.z = (compare.z);

		return vector;
	}

	public static final Vec3 max(Vec3 vector, Vec3 compare) {
		if (compare.x > vector.x)
			vector.x = (compare.x);
		if (compare.y > vector.y)
			vector.y = (compare.y);
		if (compare.z > vector.z)
			vector.z = (compare.z);

		return vector;
	}

	public static final Vec3 clamp(Vec3 vector, Vec3 min, Vec3 max) {
		if (vector.x > max.x)
			vector.x = (max.x);
		else if (vector.x < min.x)
			vector.x = (min.x);

		if (vector.y > max.y)
			vector.y = (max.y);
		else if (vector.y < min.y)
			vector.y = (min.y);

		if (vector.z > max.z)
			vector.z = (max.z);
		else if (vector.z < min.z)
			vector.z = (min.z);

		return vector;
	}

	/**
	 * NORMAL
	 */

	private static final Vec3 q = new Vec3();
	private static final Vec3 p = new Vec3();

	public static final Vec3 normal(Vec3 a, Vec3 b, Vec3 c) {
		return normal(a, b, c, new Vec3());
	}

	public static final Vec3 normal(Vec3 a, Vec3 b, Vec3 c, Vec3 r) {
		q.load(b.x - a.x, b.y - a.y, b.z - a.z);
		p.load(c.x - a.x, c.y - a.y, c.z - a.z);

		return cross(q, p, r).normalize();
	}

	/**
	 * DOT PRODUCT
	 */

	public static float dot(Vec3 a, Vec3 b) {
		return a.x * b.x + a.y * b.y + a.z * b.z;
	}

	/**
	 * CROSS PRODUCT
	 */

	public static Vec3 cross(Vec3 a, Vec3 b) {
		return cross(a, b, new Vec3());
	}

	public static Vec3 cross(Vec3 a, Vec3 b, Vec3 r) {
		r.x = (a.y * b.z - a.z * b.y);
		r.y = (a.z * b.x - a.x * b.z);
		r.z = (a.x * b.y - a.y * b.x);

		return r;
	}

	public static Vec3 reflect(Vec3 planeNormal, Vec3 incidentNormal) {
		float dot = VecMath.dot(planeNormal, incidentNormal);

		Vec3 projectedNormal = new Vec3(planeNormal).mul(dot);

		return projectedNormal.sub(incidentNormal).mul(2.0f).add(incidentNormal);
	}

	public static float sphereRayIntersection(Vec3 sphereOrigin, float sphereRadius, Ray ray) {
		Vec3 dst = sub(ray.origin, sphereOrigin);
		float B = dot(dst, ray.direction);
		float C = dot(dst, dst) - (sphereRadius * sphereRadius);
		float D = B * B - C;
		return (D > 0.0f) ? (-B - (float) Math.sqrt(D)) : Float.POSITIVE_INFINITY;
	}

	public static Vec3 planeRayIntersection(Vec3 planeNormal, float planeDistance, Ray ray) {
		Vec3 diff = new Vec3(planeNormal).length(planeDistance).sub(ray.origin);

		float dot1 = VecMath.dot(planeNormal, diff);
		float dot2 = VecMath.dot(planeNormal, ray.direction);

		return add(ray.origin, diff.load(ray.direction).mul(dot1 / dot2));
	}

	//

	public static final float angleToFlat3D(Vec3 a, Vec3 b) {
		return FastMath.atan2Deg(b.z - a.z, b.x - a.x);
	}

	public static final float angleToVertical3D(Vec3 a, Vec3 b) {
		return FastMath.atan2Deg(b.y - a.y, VecMath.distanceFlat(a, b));
	}

	public static final float angleToFlat3DStrict(Vec3 a, Vec3 b) {
		return (float) (Math.atan2(b.z - a.z, b.x - a.x) * 180.0 / Math.PI);
	}

	public static final float angleToVertical3DStrict(Vec3 a, Vec3 b) {
		return (float) (Math.atan2(b.y - a.y, VecMath.distanceFlat(a, b)) * 180.0 / Math.PI);
	}

	/**
	 * DISTANCE
	 */

	public static final float distance(Vec3 a, Vec3 b) {
		float x = a.x - b.x;
		float y = a.y - b.y;
		float z = a.z - b.z;

		return (float) Math.sqrt(x * x + y * y + z * z);
	}

	public static final float distanceFlat(Vec3 a, Vec3 b) {
		float x = a.x - b.x;
		float z = a.z - b.z;

		return (float) Math.sqrt(x * x + z * z);
	}

	/**
	 * SQUARED DISTANCE
	 */

	public static final float squaredDistance(Vec3 a, Vec3 b) {
		float x = a.x - b.x;
		float y = a.y - b.y;
		float z = a.z - b.z;

		return x * x + y * y + z * z;
	}

	public static final float squaredDistanceFlat(Vec3 a, Vec3 b) {
		float x = a.x - b.x;
		float z = a.z - b.z;

		return x * x + z * z;
	}

	/**
	 * RANGE
	 */

	public static final boolean isInRange(Sphere a, Sphere b) {
		return isInRange(a.origin, b.origin, a.radius + b.radius);
	}

	public static final boolean isInRange(Vec3 a, Vec3 b, float d) {
		float x = a.x - b.x;
		float y = a.y - b.y;
		float z = a.z - b.z;

		return (x * x + y * y + z * z) < (d * d);
	}

	public static final boolean isInRangeFlat(Vec3 a, Vec3 b, float d) {
		float x = a.x - b.x;
		float z = a.z - b.z;

		return (x * x + z * z) < (d * d);
	}

	/**
	 * LERP
	 */

	public static final Vec2 lerp(float t, Vec2 a, Vec2 b) {
		return lerp(t, a, b, new Vec2());
	}

	public static final Vec3 lerp(float t, Vec3 a, Vec3 b) {
		return lerp(t, a, b, new Vec3());
	}

	//

	public static final Vec2 lerp(float t, Vec2 a, Vec2 b, Vec2 r) {
		r.x = (a.x + t * (b.x - a.x));
		r.y = (a.y + t * (b.y - a.y));

		return r;
	}

	public static final Vec3 lerp(float t, Vec3 a, Vec3 b, Vec3 r) {
		r.x = (a.x + t * (b.x - a.x));
		r.y = (a.y + t * (b.y - a.y));
		r.z = (a.z + t * (b.z - a.z));

		return r;
	}
}