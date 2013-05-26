/*
 * Created on 12 sep 2008
 */

package craterstudio.text;

import java.util.Calendar;

import craterstudio.math.EasyMath;
import craterstudio.time.DateMath;

public class TextDateTime {
	public static String set(int yyyy, int mm, int dd, int h, int m, int s) {
		return TextDate.set(yyyy, mm, dd) + ' ' + TextTime.set(h, m, s);
	}

	public static String min(Iterable<String> dates) {
		String min = null;
		for (String date : dates)
			if (min == null || lessThan(date, min))
				min = date;
		return min;
	}

	public static String max(Iterable<String> dates) {
		String max = null;
		for (String date : dates)
			if (max == null || greaterThan(date, max))
				max = date;
		return max;
	}

	public static boolean equals(String a, String b) {
		return TextDateTime.compare(a, b) == 0;
	}

	public static boolean lessThan(String a, String b) {
		return TextDateTime.compare(a, b) < 0;
	}

	public static boolean greaterThan(String a, String b) {
		return TextDateTime.compare(a, b) > 0;
	}

	public static boolean lessThanOrEquals(String a, String b) {
		return TextDateTime.compare(a, b) <= 0;
	}

	public static boolean greaterThanOrEquals(String a, String b) {
		return TextDateTime.compare(a, b) >= 0;
	}

	public static boolean between(String s, String lo, String hi) {
		return TextDateTime.greaterThanOrEquals(s, lo) && TextDateTime.lessThanOrEquals(s, hi);
	}

	public static Calendar toCalendar(String ss) {
		TextDateTime.check(ss);

		Calendar c = Calendar.getInstance();
		c.clear();
		c.set(year(ss), month(ss) - 1, day(ss), hour(ss), minute(ss), second(ss));
		return c;
	}

	public static String fromCalendar(Calendar c) {
		return TextDate.fromCalendar(c) + " " + TextTime.fromCalendar(c);
	}

	public static String now() {
		return fromCalendar(Calendar.getInstance());
	}

	public static String fromEpoch(long millis) {
		Calendar c = Calendar.getInstance();
		c.setTimeInMillis(millis);
		return fromCalendar(c);
	}

	public static long toEpoch(String ss) {
		return toCalendar(ss).getTimeInMillis();
	}

	public static String traverseDays(String ss, int days) {
		String date = TextDateTime.toDate(ss);
		String time = TextDateTime.toTime(ss);

		date = TextDate.traverseDays(date, days);

		return date + ' ' + time;
	}

	private static final int SECONDS_IN_DAY = 60 * 60 * 24;

	public static String traverseSeconds(String ss, long traverseSeconds) {
		String date = TextDateTime.toDate(ss);
		String time = TextDateTime.toTime(ss);

		long secondsThisDay = TextTime.timeToSec(time) + traverseSeconds;

		int traverseDate = (int) (secondsThisDay / SECONDS_IN_DAY);
		if (secondsThisDay < 0)
			traverseDate -= 1;

		date = TextDate.traverseDays(date, traverseDate);
		time = TextTime.secToTime(EasyMath.moduloAbs((int) secondsThisDay, SECONDS_IN_DAY));

		return date + ' ' + time;
	}

	public static long diffInSec(String from, String until) {
		int dayDiff = TextDate.daySpan(TextDateTime.toDate(from), TextDateTime.toDate(until)) - 1;
		int secDiff = TextTime.diffInSec(TextDateTime.toTime(from), TextDateTime.toTime(until));

		return (dayDiff * 24L * 60L * 60L) + secDiff;
	}

	public static boolean is(String s) {
		// YYYY-MM-DD HH:MM:SS
		if (s.length() != 19)
			return false;

		if (s.charAt(10) != ' ')
			return false;

		if (!TextDate.is(s.substring(0, 10)))
			return false;
		if (!TextTime.is(s.substring(11)))
			return false;

		return true;
	}

	public static String check(String s) {
		if (!TextDateTime.is(s)) {
			if (s.length() == 8)
				throw new IllegalArgumentException("probably a TIME instead of DATETIME: '" + s + "'");
			if (s.length() == 10)
				throw new IllegalArgumentException("probably a DATE instead of DATETIME: '" + s + "'");
			throw new IllegalArgumentException(s);
		}
		return s;
	}

	public static int compare(String a, String b) {
		TextDateTime.check(a);
		TextDateTime.check(b);

		int diff;
		for (int i = 0; i < 19; i++)
			if ((diff = a.charAt(i) - b.charAt(i)) != 0)
				return diff;
		return 0;
	}

	public static String toDate(String s) {
		if (s.length() != 19)
			throw new IllegalArgumentException();
		return s.substring(0, 10);
	}

	public static String toTime(String s) {
		if (s.length() != 19)
			throw new IllegalArgumentException();
		return s.substring(11);
	}

	public static int year(String ss) {
		return Integer.parseInt(ss.substring(0, 4));
	}

	public static int month(String ss) {
		return Integer.parseInt(ss.substring(5, 7));
	}

	public static int day(String ss) {
		return Integer.parseInt(ss.substring(8, 10));
	}

	public static int hour(String ss) {
		return Integer.parseInt(ss.substring(11, 13));
	}

	public static int minute(String ss) {
		return Integer.parseInt(ss.substring(14, 16));
	}

	public static int second(String ss) {
		return Integer.parseInt(ss.substring(17, 19));
	}
}
