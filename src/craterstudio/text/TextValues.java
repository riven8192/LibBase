/*
 * Created on Sep 18, 2005
 */

package craterstudio.text;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Calendar;

public class TextValues {
	/**
	 * PARSE
	 */

	public static boolean isBoolean(String value) {
		if (value == null)
			return false;
		if (value.equalsIgnoreCase("true"))
			return true;
		if (value.equalsIgnoreCase("false"))
			return true;
		return false;
	}

	public static boolean isInt(String value) {
		if (value == null) {
			return false;
		}

		try {
			Integer.parseInt(value);
			return true;
		} catch (NumberFormatException exc) {
			return false;
		}
	}

	public static boolean isLong(String value) {
		if (value == null) {
			return false;
		}

		try {
			Long.parseLong(value);
			return true;
		} catch (NumberFormatException exc) {
			return false;
		}
	}

	public static boolean isFloat(String value) {
		if (value == null) {
			return false;
		}

		try {
			Float.parseFloat(value);
			return true;
		} catch (NumberFormatException exc) {
			return false;
		}
	}

	public static boolean isDouble(String value) {
		if (value == null) {
			return false;
		}

		try {
			Double.parseDouble(value);
			return true;
		} catch (NumberFormatException exc) {
			return false;
		}
	}

	public static boolean tryParseBoolean(String value, boolean defaultValue) {
		if (value == null) {
			return defaultValue;
		}

		return Boolean.parseBoolean(value);
	}

	public static int tryParseInt(String value, int defaultValue) {
		if (value == null) {
			return defaultValue;
		}

		try {
			return Integer.parseInt(value);
		} catch (NumberFormatException exc) {
			return defaultValue;
		}
	}

	public static long tryParseLong(String value, long defaultValue) {
		if (value == null) {
			return defaultValue;
		}

		try {
			return Long.parseLong(value);
		} catch (NumberFormatException exc) {
			return defaultValue;
		}
	}

	public static float tryParseFloat(String value, float defaultValue) {
		if (value == null) {
			return defaultValue;
		}

		try {
			return Float.parseFloat(value);
		} catch (NumberFormatException exc) {
			return defaultValue;
		}
	}

	public static double tryParseDouble(String value, double defaultValue) {
		if (value == null) {
			return defaultValue;
		}

		try {
			return Double.parseDouble(value);
		} catch (NumberFormatException exc) {
			return defaultValue;
		}
	}

	public static final String[] trim(String[] src) {
		String[] dst = new String[src.length];
		for (int i = 0; i < dst.length; i++)
			dst[i] = src[i].trim();
		return dst;
	}

	//

	public static final boolean[] parseBooleans(String[] value) {
		boolean[] data = new boolean[value.length];
		for (int i = 0; i < data.length; i++)
			if (value[i].equals("true"))
				data[i] = true;
			else if (value[i].equals("false"))
				data[i] = false;
			else
				throw new IllegalArgumentException("value: " + value[i]);
		return data;
	}

	public static final long[] parseLongs(String[] value) {
		long[] data = new long[value.length];
		for (int i = 0; i < data.length; i++)
			data[i] = Long.parseLong(value[i], 10);
		return data;
	}

	public static final double[] parseDoubles(String[] value) {
		double[] data = new double[value.length];
		for (int i = 0; i < data.length; i++)
			data[i] = Double.parseDouble(value[i]);
		return data;
	}

	//

	public static final int[] parseInts(String[] value) {
		return TextValues.parseInts(value, 0, value.length, 10);
	}

	public static final int[] parseInts(String[] value, int radix) {
		return TextValues.parseInts(value, 0, value.length, radix);
	}

	public static final int[] parseInts(String[] value, int off, int len) {
		return TextValues.parseInts(value, off, len, 10);
	}

	public static final int[] parseInts(String[] value, int off, int len, int radix) {
		int[] data = new int[len];
		for (int i = 0; i < len; i++)
			data[i] = Integer.parseInt(value[off + i], radix);
		return data;
	}

	public static final float[] parseFloats(String[] value) {
		return TextValues.parseFloats(value, 0, value.length);
	}

	public static final float[] parseFloats(String[] value, int off, int len) {
		float[] data = new float[len];

		for (int i = 0; i < len; i++)
			data[i] = Float.parseFloat(value[off + i]);

		return data;
	}

	public static final String nanosToTime(long nanos) {
		if (nanos == 0)
			return "n/a"; // so small it cannot even be the time elapsed between
			              // two System.nanoTime() calls

		if (nanos < 10000)
			return nanos + "ns";

		long micros = nanos / 1000L;
		if (micros < 10000)
			return micros + "us";

		long millis = micros / 1000L;
		if (millis < 10000)
			return millis + "ms";

		return millis / 1000 + "s";
	}

	public static final String nanosAsMicroSeconds(long nanos) {
		return TextValues.formatNumber(nanos / 1000000000.0, 6) + "s";
	}

	/**
	 * VALUE OF
	 */

	public static final String valueOf(int[] buf) {
		return TextValues.valueOf(buf, 0, buf.length);
	}

	public static final String valueOf(float[] buf) {
		return TextValues.valueOf(buf, 0, buf.length);
	}

	public static final String valueOf(int[] buf, int off, int len) {
		if (len == 0)
			return "";

		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i < len; i++) {
			buffer.append(buf[off + i]);
			buffer.append(", ");
		}

		buffer.setLength(buffer.length() - 2);

		return buffer.toString();
	}

	public static final String valueOf(float[] buf, int off, int len) {
		if (len == 0)
			return "";

		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i < len; i++) {
			buffer.append(buf[off + i]);
			buffer.append(", ");
		}

		buffer.setLength(buffer.length() - 2);

		return buffer.toString();
	}

	/**
	 * HEX
	 */

	private static char[] hexTableUpper = "0123456789ABCDEF".toCharArray();

	// private static char[] hexTableLower = "0123456789abcdef".toCharArray();

	private static final int h2i(int cur) {
		if (cur >= '0' && cur <= '9')
			return cur - '0';
		if (cur >= 'a' && cur <= 'f')
			return cur - 'a' + 10;
		if (cur >= 'A' && cur <= 'F')
			return cur - 'A' + 10;
		throw new IllegalArgumentException("cur=" + cur);
	}

	public static final String hexDecode(String hex) {
		if (hex == null)
			return null;
		if (hex.length() % 2 != 0)
			throw new IllegalArgumentException();

		char[] digits = new char[hex.length() / 2];
		for (int k = 0, p = 0; k < digits.length; k++)
			digits[k] = (char) ((h2i(hex.charAt(p++)) << 4) | h2i(hex.charAt(p++)));
		return new String(digits);
	}

	public static final String hexEncode(String str) {
		if (str == null)
			return null;

		char[] hex = new char[str.length() * 2];
		for (int i = 0, p = 0; i < str.length(); i++, p += 2) {
			char c = str.charAt(i);
			hex[p + 0] = hexTableUpper[(c & 0xF0) >> 4];
			hex[p + 1] = hexTableUpper[(c & 0x0F) >> 0];
		}
		return new String(hex);
	}

	//

	public static int hexDecodeDigit(char c) {
		if (c >= '0' && c <= '9')
			return c - '0';
		if (c >= 'a' && c <= 'f')
			return 10 + (c - 'a');
		if (c >= 'A' && c <= 'F')
			return 10 + (c - 'A');
		throw new IllegalStateException();
	}

	//

	public static final String hexRawEncode(byte[] raw) {
		char[] ca = new char[raw.length * 2];
		for (int i = 0; i < raw.length; i++)
			for (int k = 0; k < 2; k++)
				ca[(i << 1) + (1 - k)] = hexTableUpper[((raw[i] & 0xFF) >>> (k << 2)) & 0x0F];
		return new String(ca);
	}

	public static final byte[] hexRawDecode(String raw) {
		if (raw.length() % 2 != 0)
			throw new IllegalStateException();

		byte[] data = new byte[raw.length() >> 1];
		for (int i = 0; i < data.length; i++)
			data[i] = (byte) Integer.parseInt(raw.substring(i << 1, (i << 1) + 2), 16);
		return data;
	}

	//

	public static final String hexValueOf(byte hex) {
		char[] digits = new char[2];
		for (int i = 0; i < 2; i++)
			digits[1 - i] = hexTableUpper[(hex >>> (i << 2)) & 0x0F];
		return new String(digits);
	}

	public static final String hexValueOf(short hex) {
		char[] digits = new char[4];
		for (int i = 0; i < 4; i++)
			digits[3 - i] = hexTableUpper[(hex >>> (i << 2)) & 0x0F];
		return new String(digits);
	}

	public static final String hexValueOf(int hex) {
		char[] digits = new char[8];
		for (int i = 0; i < 8; i++)
			digits[7 - i] = hexTableUpper[(hex >>> (i << 2)) & 0x0F];
		return new String(digits);
	}

	public static final String hexValueOf(long hex) {
		char[] digits = new char[16];
		for (int i = 0; i < 16; i++)
			digits[15 - i] = hexTableUpper[(int) ((hex >>> (i << 2))) & 0x0F];
		return new String(digits);
	}

	/**
	 * BIN
	 */

	public static final String binValueOf(byte hex) {
		char[] digits = new char[8];
		for (int i = 0; i < 8; i++)
			digits[7 - i] = (char) ('0' + ((hex >>> i) & 0x01));
		return new String(digits);
	}

	public static final String binValueOf(short hex) {
		char[] digits = new char[3216];
		for (int i = 0; i < 16; i++)
			digits[15 - i] = (char) ('0' + ((hex >>> i) & 0x01));
		return new String(digits);
	}

	public static final String binValueOf(int hex) {
		char[] digits = new char[32];
		for (int i = 0; i < 32; i++)
			digits[31 - i] = (char) ('0' + ((hex >>> i) & 0x01));
		return new String(digits);
	}

	public static final String binValueOf(long hex) {
		char[] digits = new char[64];
		for (int i = 0; i < 64; i++)
			digits[63 - i] = (char) ('0' + ((hex >>> i) & 0x01));
		return new String(digits);
	}

	/**
	 * FORMAT
	 */

	private static final String zeros = new String("0000000000000000000000000000000000");

	public static final int parseIntMagnitude(String s) {
		long value = parseLongMagnitude(s);
		if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE)
			throw new IllegalStateException("value too large too fit in integer");
		return (int) value;
	}

	public static final long parseLongMagnitude(String s) {
		s = s.trim();
		if (s.isEmpty())
			return 0;

		long mul = 1;

		switch (s.charAt(s.length() - 1)) {
		// bytes: tera, giga, mega, kilo
			case 'T':
				mul *= 1024L;
			case 'G':
				mul *= 1024L;
			case 'M':
				mul *= 1024L;
			case 'K':
				mul *= 1024L;
				break;

			// milliseconds: years, <<_NO_MONTHS_>> weeks, days, hours, minutes,
			// seconds
			case 'y':
				mul *= 365L;
			case 'w':
				mul *= 7L;
			case 'd':
				mul *= 24L;
			case 'h':
				mul *= 60L;
			case 'm':
				mul *= 60L;
			case 's':
				mul *= 1000L;
				break;

			// no magnitude set
			default:
				break;
		}

		if (mul != 1) // magnitude set, strip magnitude
			s = s.substring(0, s.length() - 1);
		return Long.parseLong(s) * mul;
	}

	public static final String magnitudePeriods(int value, char sep) {
		boolean neg = value < 0;
		if (neg)
			value = -value;

		String left = String.valueOf(value);

		String build = "";
		while (left.length() > 3) {
			build = sep + left.substring(left.length() - 3) + build;
			left = left.substring(0, left.length() - 3);
		}

		return (neg ? "-" : "") + left + build;
	}

	public static final String formatCurrencyInCents(int amount, boolean formatForUSD, boolean magnitudeSeparators) {
		int full = amount / 100;
		int cent = amount % 100;

		char mags = formatForUSD ? ',' : '.';
		char sepe = formatForUSD ? '.' : ',';

		String post = sepe + formatNumber(cent, 2);
		if (magnitudeSeparators)
			return magnitudePeriods(full, mags) + post;
		return String.valueOf(full) + post;
	}

	public static final String formatNumber(int value, int minbfor) {
		boolean negative = value < 0;
		String sign = "";

		if (negative) {
			sign = "-";
			value = -value;
		}

		String s = String.valueOf(value);
		if (s.length() < minbfor)
			s = zeros.substring(0, minbfor - s.length()) + s;
		return sign + s;
	}

	public static final String formatNumber(double value, int decimals) {
		return formatNumber(value, 1, decimals);
	}

	public static final String formatNumber(double value, int minbfor, int decimals) {
		if (Double.isNaN(value))
			return "NaN";
		if (Double.isInfinite(value))
			return "Infinity";

		NumberFormat df = DecimalFormat.getInstance();
		df.setGroupingUsed(false);
		df.setMinimumFractionDigits(decimals);
		df.setMaximumFractionDigits(decimals);
		df.setMinimumIntegerDigits(value < 0.0 ? minbfor - 1 : minbfor);
		df.setMaximumIntegerDigits(Integer.MAX_VALUE);
		return df.format(value);
	}

	public static final String formatedValueOf(float[] value, int before, int after) {
		if (value.length == 0)
			return "";

		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i < value.length; i++) {
			buffer.append(TextValues.formatNumber(value[i], before, after));
			buffer.append(", ");
		}

		buffer.setLength(buffer.length() - 2);

		return buffer.toString();
	}

	/**
	 * NUMBER FORMAT
	 */

	/**
	 * MAG
	 */

	public static final String formatWithMagnitude(double value, int decimals) {
		return TextValues.formatWithMagnitude(value, decimals, 1000.0);
	}

	public static final String formatWithMagnitudeBytes(double value, int decimals) {
		return TextValues.formatWithMagnitude(value, decimals, 1024.0);
	}

	private static final String[] mags = new String[] { "n", "u", "m", "", "k", "M", "G", "T", "P" };

	private static final String formatWithMagnitude(double value, int decimals, double magSize) {
		if (value == 0.0)
			return TextValues.formatNumber(value, decimals);

		int mag = 3;
		boolean minus = value < 0.0F;

		// always make it positive
		if (minus)
			value = -value;

		if (value > 1.0F) {
			// find mag
			while ((value / magSize) > 1.0f) {
				mag++;
				value /= magSize;
			}
		} else {
			// find mag
			do {
				mag--;
				value *= magSize;
			} while ((value * magSize) < 1.0f);
		}

		// make negative if it was negative
		if (minus)
			value = -value;

		return TextValues.formatNumber(value, decimals) + mags[mag];
	}

	/**
	 * FORMAT TIME
	 */

	public static final String getCurrentDate() {
		return formatDateTime(System.currentTimeMillis(), "Y-M-D");
	}

	public static final String getCurrentTime() {
		return formatDateTime(System.currentTimeMillis(), "h:m:s");
	}

	public static final String getCurrentDateTime() {
		return formatDateTime(System.currentTimeMillis(), "Y-M-D h:m:s");
	}

	public static final String formatDateTime(long timestamp, String format) {
		Calendar cc = Calendar.getInstance();
		cc.setTimeInMillis(timestamp);

		int yyyy = cc.get(Calendar.YEAR);
		int mm = cc.get(Calendar.MONTH) + 1;
		int dd = cc.get(Calendar.DAY_OF_MONTH);
		int h = cc.get(Calendar.HOUR_OF_DAY);
		int m = cc.get(Calendar.MINUTE);
		int s = cc.get(Calendar.SECOND);
		int ms = cc.get(Calendar.MILLISECOND);

		String yyyy0 = TextValues.formatNumber(yyyy, 4, 0);
		String mm0 = TextValues.formatNumber(mm, 2, 0);
		String dd0 = TextValues.formatNumber(dd, 2, 0);
		String h0 = TextValues.formatNumber(h, 2, 0);
		String m0 = TextValues.formatNumber(m, 2, 0);
		String s0 = TextValues.formatNumber(s, 2, 0);
		String ms0 = TextValues.formatNumber(ms, 3, 0);

		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < format.length(); i++) {
			switch (format.charAt(i)) {
				case 'Y':
					sb.append(yyyy0);
					break;
				case 'M':
					sb.append(mm0);
					break;
				case 'D':
					sb.append(dd0);
					break;
				case 'h':
					sb.append(h0);
					break;
				case 'm':
					sb.append(m0);
					break;
				case 's':
					sb.append(s0);
					break;
				case 'S':
					sb.append(ms0);
					break;

				default:
					sb.append(format.charAt(i));
					break;
			}
		}

		return sb.toString();
	}

	public static final String formatElapsedTime(long ms, String format) {
		long s = ms / 1000;

		long ss = s % 60;
		long mm = (s / 60) % 60;
		long hh = (s / 60) / 60;

		String ss0 = TextValues.formatNumber(ss, 2, 0);
		String mm0 = TextValues.formatNumber(mm, 2, 0);
		String hh0 = TextValues.formatNumber(hh, 2, 0);

		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < format.length(); i++) {
			switch (format.charAt(i)) {
				case 'S':
					sb.append(ss0);
					break;
				case 'M':
					sb.append(mm0);
					break;
				case 'H':
					sb.append(hh0);
					break;
				default:
					sb.append(format.charAt(i));
					break;
			}
		}

		return sb.toString();
	}
}