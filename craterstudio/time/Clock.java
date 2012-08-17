/*
 * Created on 25 mei 2010
 */

package craterstudio.time;

import craterstudio.text.TextDateTime;
import craterstudio.text.TextTime;

public class Clock {
	static final long offset_time_millis = System.currentTimeMillis();
	static final long offset_time_nanos = System.nanoTime();

	static volatile long current_time_millis = query();

	public static long query() {
		long nanoDiff = (System.nanoTime() - offset_time_nanos);
		long got = offset_time_millis + (nanoDiff / 1_000_000L);

		// prevent negative delta time
		return current_time_millis = Math.max(current_time_millis, got);
	}

	public static long micros() {
		long nanoDiff = (System.nanoTime() - offset_time_nanos);
		return (offset_time_millis * 1000L) + (nanoDiff / 1000L);
	}

	public static long now() {
		return query();
	}

	static final String offset_time_datetime = TextDateTime.fromEpoch(offset_time_millis);

	static YearMonthDate offset_ymd = new YearMonthDate(TextDateTime.toDate(offset_time_datetime));
	static int offset_sec = TextTime.timeToSec(TextDateTime.toTime(offset_time_datetime));

	public static String timestamp() {
		int diff = (int) ((current_time_millis - offset_time_millis) / 1000);
		int sec = offset_sec + diff;
		YearMonthDate result = new YearMonthDate();
		DateMath.traverseDays(offset_ymd, sec / 86400, result);
		return result.toString() + " " + TextTime.secToTime(sec % 86400);
	}
}
