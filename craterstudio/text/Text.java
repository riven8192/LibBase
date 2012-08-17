/*
 * Created on Sep 7, 2004
 */
package craterstudio.text;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Random;
import java.util.Set;

import craterstudio.data.ByteList;
import craterstudio.data.tuples.Pair;

public class Text {
	public static boolean isNullOrEmpty(String value) {
		return (value==null) || value.isEmpty();
	}

	//

	public static String trimToNull(String value) {
		if (value == null)
			return null;
		value = value.trim();
		if (value.isEmpty())
			return null;
		return value;
	}

	public static String nullToEmpty(String value) {
		return (value == null) ? "" : value;
	}

	public static String concat(String... args) {
		int len = 0;
		for (int i = 0; i < args.length; i++)
			len += (args[i] = (args[i] == null ? "null" : args[i])).length();

		char[] chars = new char[len];
		for (int i = 0, p = 0; i < args.length; i++)
			for (int k = 0; k < args[i].length(); k++)
				chars[p++] = args[i].charAt(k);
		return new String(chars);
	}

	private static final char[] table = "0123456789abcdef".toCharArray();

	public static String hashAsHex(byte[] hash) {
		char[] table = Text.table;
		char[] digits = new char[hash.length << 1];
		for (int k = 0; k < hash.length; k++) {
			int h = hash[k];
			digits[(k << 1) | 1] = table[h & 0x0F];
			digits[k << 1] = table[(h & 0xF0) >> 4];
		}
		return new String(digits);
	}

	//

	private static final char[] generatecode_default_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890".toCharArray();

	public static String generateRandomCode(int len) {
		return generateRandomCode(len, generatecode_default_chars);
	}

	public static String generateRandomCode(int len, char[] chars) {
		return generateRandomCode(len, chars, new SecureRandom());
	}

	public static String generateRandomCode(int len, char[] chars, Random r) {
		char[] dst = new char[len];

		for (int i = 0; i < dst.length; i++)
			dst[i] = chars[r.nextInt(chars.length)];

		return new String(dst);
	}

	private static final int UUID_LENGTH = 16;
	private static final int UUID_MAX_ELEMENTS = 1024;
	private static Set<String> UUID_SET = new HashSet<String>();
	private static LinkedList<String> UUID_LIST = new LinkedList<String>();

	public static final synchronized String generateUniqueId() {
		// generate new UUID
		String uuid;
		do {
			uuid = Text.generateRandomCode(UUID_LENGTH);
		} while (!UUID_SET.add(uuid));

		// clean up oldest UUID
		UUID_LIST.addLast(uuid);
		if (UUID_LIST.size() > UUID_MAX_ELEMENTS)
			UUID_SET.remove(UUID_LIST.removeFirst());

		// return
		return uuid;
	}

	/**
	 * ALIGN STRING
	 */

	public static final int ALIGN_LEFT = 0;
	public static final int ALIGN_CENTER = 1;
	public static final int ALIGN_RIGHT = 2;

	public static final String formatString(String text, int length) {
		return Text.formatString(text, length, ALIGN_LEFT, ' ');
	}

	public static final String formatString(String text, int length, char c) {
		return Text.formatString(text, length, ALIGN_LEFT, c);
	}

	public static final String formatString(String text, int length, int type) {
		return Text.formatString(text, length, type, ' ');
	}

	public static final String formatString(String text, int length, int type, char c) {
		if (text.length() > length) {
			if (text.length() >= 3)
				return text.substring(0, length - 3) + "...";
			return "<?>";
		}

		final char[] array = new char[length];

		if (type == Text.ALIGN_LEFT) {
			int split = text.length();

			for (int i = 0; i < split; i++)
				array[i] = text.charAt(i);

			for (int i = split; i < length; i++)
				array[i] = c;
		}

		if (type == Text.ALIGN_CENTER)
			throw new UnsupportedOperationException();

		if (type == Text.ALIGN_RIGHT) {
			int split = length - text.length();

			for (int i = 0; i < split; i++)
				array[i] = c;

			for (int i = split; i < length; i++)
				array[i] = text.charAt(i - split);
		}

		return new String(array);
	}

	/**
    * 
    */

	public static final boolean onlyNumbers(String val) {
		char[] arr = val.toCharArray();

		for (int i = 0; i < arr.length; i++) {
			char c = arr[i];
			if (c < '0' || c > '9')
				return false;
		}

		return true;
	}

	public static final boolean onlyLetters(String val) {
		char[] arr = val.toCharArray();

		for (int i = 0; i < arr.length; i++) {
			char c = arr[i];
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
				return false;
		}

		return true;
	}

	/**
	 * CONVERT
	 */

	public static final String ascii(byte[] raw, int off, int len) {
		char[] str = new char[len];
		for (int i = 0; i < len; i++)
			str[i] = (char) raw[off + i];
		return new String(str);
	}

	public static final String ascii(byte[] raw) {
		char[] str = new char[raw.length];
		for (int i = 0; i < str.length; i++)
			str[i] = (char) raw[i];
		return new String(str);
	}

	public static final byte[] ascii(String str) {
		byte[] raw = new byte[str.length()];
		for (int i = 0; i < raw.length; i++)
			raw[i] = (byte) str.charAt(i);
		return raw;
	}

	public static final void ascii(OutputStream out, byte[] tmp, String str) throws IOException {
		int pos = 0;
		for (int i = 0; i < str.length(); i++) {
			tmp[pos++] = (byte) str.charAt(i);
			if (pos == tmp.length) {
				out.write(tmp, 0, pos);
				pos = 0;
			}
		}
		out.write(tmp, 0, pos);
	}

	public static String toLower(String s) {
		char[] ca = s.toCharArray();
		for (int i = 0; i < ca.length; i++) {
			ca[i] = toLower(ca[i]);
		}
		return new String(ca);
	}

	public static String toUpper(String s) {
		char[] ca = s.toCharArray();
		for (int i = 0; i < ca.length; i++) {
			ca[i] = toUpper(ca[i]);
		}
		return new String(ca);
	}

	public static char toLower(char c) {
		return (c >= 'A' && c <= 'Z') ? (char) (c + ('a' - 'A')) : c;
	}

	public static char toUpper(char c) {
		return (c >= 'a' && c <= 'z') ? (char) (c - ('a' - 'A')) : c;
	}

	//

	public static final String utf8(byte[] raw) {
		return Text.utf8(raw, 0, raw.length);
	}

	public static final String utf8(byte[] raw, int off, int len) {
		try {
			return new String(raw, off, len, "UTF-8");
		} catch (UnsupportedEncodingException exc) {
			throw new IllegalStateException();
		}
	}

	public static final byte[] utf8(String str) {
		try {
			return str.getBytes("UTF-8");
		} catch (UnsupportedEncodingException exc) {
			throw new IllegalStateException();
		}
	}

	//

	private static final String encoding = "ISO-8859-1"; // "UTF-8";

	public static final String convert(byte[] data) {
		return convert(data, encoding);
	}

	public static final String convert(byte[] data, String encoding) {
		try {
			return new String(data, encoding);
		} catch (Exception exc) {
			return null;
		}
	}

	public static final String convert(byte[] data, int offset, int length) {
		try {
			return new String(data, offset, length, encoding);
		} catch (Exception exc) {
			return null;
		}
	}

	public static final byte[] convert(String value) {
		try {
			return value.getBytes(encoding);
		} catch (Exception exc) {
			return null;
		}
	}

	/**
	 * CHOP LAST
	 */

	public static String chopLast(String value, int chars) {
		if (chars < 0 || chars > value.length())
			throw new IllegalArgumentException("invalid chars: " + chars + " / " + value.length());
		return value.substring(0, value.length() - chars);
	}

	public static StringBuilder chopLast(StringBuilder value, int chars) {
		if (chars < 0 || chars > value.length())
			throw new IllegalArgumentException("invalid chars: " + chars + " / " + value.length());
		value.setLength(value.length() - chars);
		return value;
	}

	/**
	 * FLIP
	 */

	public static final String flip(String value) {
		char[] arr = value.toCharArray();

		int half = arr.length / 2;
		int end = arr.length - 1;

		for (int i = 0; i < half; i++) {
			char c = arr[i];
			arr[i] = arr[end - i];
			arr[end - i] = c;
		}

		return String.valueOf(arr);
	}

	public static String firstOccurence(String text, String... finds) {
		int min = Integer.MAX_VALUE;
		String first = null;
		for (String find : finds) {
			int i = text.indexOf(find);
			if (i != -1 && i < min) {
				min = i;
				first = find;
			}
		}
		return first;
	}

	public static Pair<String, Integer> firstOccurenceWithIndex(String text, String... finds) {
		int min = Integer.MAX_VALUE;
		String first = null;
		for (String find : finds) {
			int i = text.indexOf(find);
			if (i != -1 && i < min) {
				min = i;
				first = find;
			}
		}
		if (first == null)
			return null;
		return new Pair<String, Integer>(first, Integer.valueOf(min));
	}

	/**
	 * SPLIT
	 */

	public static final String[] depthAwareSplit(String value, char split, char open, char close) {
		List<String> list = new ArrayList<String>();

		int depth = 0;
		int lastStart = 0;

		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);

			if (c == open) {
				depth++;
				continue;
			}

			if (c == close) {
				depth--;
				continue;
			}

			if (c != split || depth != 0) {
				continue;
			}

			list.add(value.substring(lastStart, i));
			lastStart = i + 1;
		}

		if (lastStart != value.length())
			list.add(value.substring(lastStart));

		return list.toArray(new String[list.size()]);
	}

	public static final String normalizeLinebreaks(String value) {
		value = Text.replace(value, "\r\n", "\n");
		value = Text.replace(value, '\r', '\n');

		return value;
	}

	public static final String[] splitOnLines(String value) {
		return Text.split(normalizeLinebreaks(value), '\n');
	}

	public static final String[] split(String value, char d) {
		String[] buf = new String[count(value, d) + 1];

		split(value, d, buf);

		return buf;
	}

	public static final String[] splitOnUnicodeWhitespace(String value) {
		List<String> parts = new ArrayList<String>();

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < value.length(); i++) {
			if (Character.isWhitespace(value.charAt(i))) {
				parts.add(sb.toString());
				sb.setLength(0);
			} else {
				sb.append(value.charAt(i));
			}
		}
		parts.add(sb.toString());
		sb.setLength(0);

		return parts.toArray(new String[parts.size()]);
	}

	public static final String[] split(String value, String d) {
		List<String> parts = new ArrayList<String>();

		String[] buf = new String[2];
		String[] pair;

		while ((pair = splitPair(value, d, buf)) != null) {
			parts.add(pair[0]);
			value = pair[1];
		}

		parts.add(value);

		return parts.toArray(new String[parts.size()]);
	}

	public static final int split(String value, char d, String[] buf) {
		int count = 0, n = value.length(), lastSplit = 0;

		for (int i = 0; i < n; i++) {
			if (value.charAt(i) == d) {
				buf[count++] = value.substring(lastSplit, i);

				lastSplit = i + 1;
			}
		}

		buf[count++] = value.substring(lastSplit, n);

		return count;
	}

	/**
	 * PAIR
	 */

	public static final String[] splitPair(String pair, char d) {
		return Text.splitPair(pair, d, new String[2]);
	}

	public static final String[] splitPair(String pair, String d) {
		return Text.splitPair(pair, d, new String[2]);
	}

	public static final String[] splitPair(String pair, char d, String[] result) {
		int split = pair.indexOf(d);
		if (split == -1)
			return null;

		result[0] = pair.substring(0, split);
		result[1] = pair.substring(split + 1);

		return result;
	}

	public static final String[] splitPair(String pair, String d, String[] result) {
		int split = pair.indexOf(d);
		if (split == -1)
			return null;

		result[0] = pair.substring(0, split);
		result[1] = pair.substring(split + d.length());

		return result;
	}

	public static final String[] splitOnUppercase(String input) {
		StringBuilder part = new StringBuilder();
		List<String> parts = new ArrayList<String>();
		for (char c : input.toCharArray()) {
			if (Character.isUpperCase(c)) {
				if (part.length() > 0)
					parts.add(part.toString());
				part.setLength(0);
			}
			part.append(c);
		}
		if (part.length() > 0)
			parts.add(part.toString());
		return parts.toArray(new String[parts.size()]);
	}

	/**
	 * CHOP
	 */

	public static final String[] chop(String value, int size) {
		int fullParts = value.length() / size;
		int extra = ((value.length() % size) != 0) ? 1 : 0;

		String[] part = new String[fullParts + extra];

		for (int i = 0; i < fullParts; i++)
			part[i] = value.substring(i * size, (i + 1) * size);

		if (extra != 0)
			part[fullParts] = value.substring(fullParts * size);

		return part;
	}

	/**
	 * JOIN
	 */

	public static final String join(String[] value) {
		return Text.join(value, 0, value.length);
	}

	public static final String join(String[] value, char c) {
		return Text.join(value, 0, value.length, c);
	}

	public static final String join(String[] value, String s) {
		return Text.join(value, 0, value.length, s);
	}

	public static final String join(String[] value, int off, int len) {
		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < len; i++)
			buffer.append(value[off + i]);
		return buffer.toString();
	}

	public static final String join(String[] value, int off, int len, char c) {
		StringBuilder buffer = new StringBuilder();

		for (int i = 0; i < len; i++) {
			buffer.append(value[off + i]);
			if (i != len - 1)
				buffer.append(c);
		}

		return buffer.toString();
	}

	public static final String join(String[] value, int off, int len, String s) {
		StringBuilder buffer = new StringBuilder();

		for (int i = 0; i < len; i++) {
			buffer.append(value[off + i]);
			if (i != len - 1)
				buffer.append(s);
		}

		return buffer.toString();
	}

	public static final String[] multiSplit(String value, char... cs) {
		int[] in = new int[cs.length];
		int or = 0;
		for (int i = 0; i < in.length; i++)
			if ((or |= in[i] = value.indexOf(cs[i], i == 0 ? 0 : in[i - 1] + 1)) < 0)
				return null;

		String[] parts = new String[cs.length + 1];
		for (int i = 0; i < parts.length - 1; i++)
			parts[i] = value.substring(i == 0 ? 0 : in[i - 1] + 1, in[i]);
		parts[parts.length - 1] = value.substring(in[in.length - 1] + 1);

		return parts;
	}

	// INPUT: "abc def_ghi jkl_mno pqr" & [" ","_"]
	// OUTPUT: ["abc","def","ghi","jkl","mno pqr"]

	public static final String[] multiSplit(String value, String... ss) {
		int[] in = new int[ss.length];
		int or = 0;
		for (int i = 0; i < ss.length; i++)
			if ((or |= in[i] = value.indexOf(ss[i], i == 0 ? 0 : in[i - 1] + ss[i - 1].length())) < 0)
				return null;

		String[] parts = new String[ss.length + 1];
		for (int i = 0; i < parts.length - 1; i++)
			parts[i] = value.substring(i == 0 ? 0 : in[i - 1] + ss[i - 1].length(), in[i]);
		parts[parts.length - 1] = value.substring(in[in.length - 1] + ss[ss.length - 1].length());

		return parts;
	}

	public static final String[] multiSplitAll(String value, char... cs) {
		List<String> results = new ArrayList<String>();

		while (value != null) {
			String[] result = Text.multiSplit(value, cs);

			if (result == null) {
				results.add(value);
				value = null;
			} else {
				for (int i = 0; i < result.length - 1; i++)
					results.add(result[i]);
				value = result[result.length - 1];
			}
		}

		return results.toArray(new String[results.size()]);
	}

	public static final String[] multiSplitLoop_bugged(String value, char... cs) {
		List<String> results = new ArrayList<String>();

		while (value != null) {
			String[] result = Text.multiSplit(value, cs);

			if (result == null) {
				results.add(value);
				value = null;
			} else {
				for (int i = 0; i < result.length - 1; i++)
					results.add(result[i]);
				value = result[result.length - 1];
			}
		}

		return results.toArray(new String[results.size()]);
	}

	public static final String[] multiSplitLoop_bugged(String value, String... ss) {
		List<String> results = new ArrayList<String>();

		while (value != null) {
			String[] result = Text.multiSplit(value, ss);

			if (result == null) {
				results.add(value);
				value = null;
			} else {
				for (int i = 0; i < result.length - 1; i++)
					results.add(result[i]);
				value = result[result.length - 1];
			}
		}

		return results.toArray(new String[results.size()]);
	}

	/**
	 * BEFORE / AFTER / BETWEEN
	 */

	public static String before(String text, char find) {
		int offset = text.indexOf(find);
		if (offset == -1)
			return null;
		return text.substring(0, offset);
	}

	public static String before(String text, String find) {
		int offset = text.indexOf(find);
		if (offset == -1)
			return null;
		return text.substring(0, offset);
	}

	public static String beforeLast(String text, char find) {
		int offset = text.lastIndexOf(find);
		if (offset == -1)
			return null;
		return text.substring(0, offset);
	}

	public static String beforeLast(String text, String find) {
		int offset = text.lastIndexOf(find);
		if (offset == -1)
			return null;
		return text.substring(0, offset);
	}

	//

	public static String after(String text, char find) {
		int offset = text.indexOf(find);
		if (offset == -1)
			return null;
		return text.substring(offset + 1);
	}

	public static String after(String text, String find) {
		int offset = text.indexOf(find);
		if (offset == -1)
			return null;
		return text.substring(offset + find.length());
	}

	public static String afterLast(String text, char find) {
		int offset = text.lastIndexOf(find);
		if (offset == -1)
			return null;
		return text.substring(offset + 1);
	}

	public static String afterLast(String text, String find) {
		int offset = text.lastIndexOf(find);
		if (offset == -1)
			return null;
		return text.substring(offset + find.length());
	}

	//

	public static String betweenOuter(String text, char start, char end) {
		String after = Text.after(text, start);
		if (after == null)
			return null;
		return Text.beforeLast(after, end);
	}

	public static String betweenOuter(String text, String start, String end) {
		String after = Text.after(text, start);
		if (after == null)
			return null;
		return Text.beforeLast(after, end);
	}

	//

	public static String between(String text, char start, char end) {
		String after = Text.after(text, start);
		if (after == null)
			return null;
		return Text.before(after, end);
	}

	public static String between(String text, String start, String end) {
		String after = Text.after(text, start);
		if (after == null)
			return null;
		return Text.before(after, end);
	}

	public static String between(String text, char start, char end, String def) {
		return Text.replaceOnNull(Text.between(text, start, end), def);
	}

	public static String between(String text, String start, String end, String def) {
		return Text.replaceOnNull(Text.between(text, start, end), def);
	}

	public static String[] multiBetween(String text, String start, String end) {
		List<String> matches = new ArrayList<String>();

		while (true) {
			String afterStart = Text.after(text, start);
			if (afterStart == null)
				break;
			String[] matchAndNext = Text.splitPair(afterStart, end);
			if (matchAndNext == null)
				break;
			matches.add(matchAndNext[0]);
			text = matchAndNext[1];
		}

		return matches.toArray(new String[matches.size()]);
	}

	//

	private static String replaceOnNull(String text, String replace) {
		return (text == null) ? replace : text;
	}

	//

	public static String beforeIfAny(String text, char find) {
		return Text.replaceOnNull(Text.before(text, find), text);
	}

	public static String beforeIfAny(String text, String find) {
		return Text.replaceOnNull(Text.before(text, find), text);
	}

	public static String beforeLastIfAny(String text, char find) {
		return Text.replaceOnNull(Text.beforeLast(text, find), text);
	}

	public static String beforeLastIfAny(String text, String find) {
		return Text.replaceOnNull(Text.beforeLast(text, find), text);
	}

	//

	public static String afterIfAny(String text, char find) {
		return Text.replaceOnNull(Text.after(text, find), text);
	}

	public static String afterIfAny(String text, String find) {
		return Text.replaceOnNull(Text.after(text, find), text);
	}

	public static String afterLastIfAny(String text, char find) {
		return Text.replaceOnNull(Text.afterLast(text, find), text);
	}

	public static String afterLastIfAny(String text, String find) {
		return Text.replaceOnNull(Text.afterLast(text, find), text);
	}

	//

	public static String before(String text, char find, String def) {
		return Text.replaceOnNull(Text.before(text, find), def);
	}

	public static String before(String text, String find, String def) {
		return Text.replaceOnNull(Text.before(text, find), def);
	}

	public static String beforeLast(String text, char find, String def) {
		return Text.replaceOnNull(Text.beforeLast(text, find), def);
	}

	public static String beforeLast(String text, String find, String def) {
		return Text.replaceOnNull(Text.beforeLast(text, find), def);
	}

	public static String after(String text, char find, String def) {
		return Text.replaceOnNull(Text.after(text, find), def);
	}

	public static String after(String text, String find, String def) {
		return Text.replaceOnNull(Text.after(text, find), def);
	}

	public static String afterLast(String text, char find, String def) {
		return Text.replaceOnNull(Text.afterLast(text, find), def);
	}

	public static String afterLast(String text, String find, String def) {
		return Text.replaceOnNull(Text.afterLast(text, find), def);
	}

	/**
    * 
    */

	public static final int[] indicesOf(String s, char c) {
		int[] p = new int[Text.count(s, c)];

		for (int i = 0, j = 0; i < s.length(); i++)
			if (s.charAt(i) == c)
				p[j++] = i;

		return p;
	}

	public static final int[] indicesOf(String s, String m) {
		if (m.length() == 0)
			throw new IllegalArgumentException("empty match");

		int[] p = new int[Text.count(s, m)];
		int i = 0;

		int offset = 0;
		while (true) {
			int off = s.indexOf(m, offset);
			if (off == -1)
				break;
			p[i++] = off;
			offset = off + m.length();
		}
		return p;
	}

	/**
	 * COUNT
	 */

	public static final int count(String s, char d) {
		int n = s.length(), x = 0;

		for (int i = 0; i < n; i++)
			if (s.charAt(i) == d)
				x++;

		return x;
	}

	public static final int count(String s, String d) {
		int count = 0, offset = 0;
		while (true) {
			int off = s.indexOf(d, offset);
			if (off == -1)
				break;
			count++;
			offset = off + d.length();
		}
		return count;
	}

	public static String repeat(String s, int count) {
		if (count < 0)
			throw new IllegalArgumentException();
		if (count == 0)
			return "";
		if (count == 1)
			return s;

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < count; i++)
			sb.append(s);
		return sb.toString();
	}

	public static String repeat(char c, int count) {
		if (count < 0)
			throw new IllegalArgumentException();
		if (count == 0)
			return "";
		if (count == 1)
			return String.valueOf(c);

		char[] cs = new char[count];
		for (int i = 0; i < count; i++)
			cs[i] = c;
		return new String(cs);
	}

	/**
	 * REPLACE
	 */

	public static final String replaceBetweenIfAny(String s, String open, String close, String replaceWith) {
		int i = s.indexOf(open);
		if (i == -1 || s.indexOf(close, i + open.length()) == -1)
			return s; // early escape

		String a = Text.before(s, open);
		if (a == null)
			return s; // not so early escape
		String b = Text.after(Text.after(s, open), close);
		if (b == null)
			return s;
		return a + open + replaceWith + close + b;
	}

	public static final String replaceAllBetween(String s, String open, String close, String replaceWith) {
		if (s.indexOf(open) == -1 || s.indexOf(close) == -1)
			return s; // early escape

		String remaining = s;
		StringBuilder done = new StringBuilder();

		while (true) {
			int indexOfOpen = remaining.indexOf(open);
			if (indexOfOpen == -1)
				break;

			int indexOfClose = remaining.indexOf(close, indexOfOpen + open.length());
			if (indexOfClose == -1)
				break;

			String before = remaining.substring(0, indexOfOpen);
			done.append(before);
			if (replaceWith != null)
				done.append(replaceWith);
			remaining = remaining.substring(indexOfClose + close.length());
		}

		return done.append(remaining).toString();
	}

	public static final String replace(String s, char a, char b) {
		if (s.indexOf(a) == -1)
			return s; // early escape

		char[] array = s.toCharArray();
		for (int i = 0; i < array.length; i++)
			if (array[i] == a)
				array[i] = b;
		return new String(array);
	}

	public static final String replace(String s, String a, String b) {
		if (s.indexOf(a) == -1)
			return s; // early escape

		StringBuilder sb = new StringBuilder();

		int len = a.length();
		int off = 0;

		while (true) {
			int found = s.indexOf(a, off);

			if (found == -1) {
				sb.append(s.substring(Math.min(off, s.length())));

				break;
			}

			sb.append(s.substring(off, found));
			sb.append(b);

			off += (found - off) + len;
		}

		return sb.toString();
	}

	public static final String replaceIfEquals(String s, String a, String b) {
		if (s == null)
			return (a == null) ? b : s;
		return s.equals(a) ? b : s;
	}

	/**
	 * REMOVE
	 */

	public static final String removeInnerIfAny(String s, String open, String close) {
		String a = Text.before(s, open);
		if (a == null)
			return s;
		String b = Text.after(s, open);
		if (b.startsWith(close))
			return s;
		String c = Text.after(b, close);
		if (c == null)
			return s;
		return a + open + close + c;
	}

	public static final String removeOuterIfAny(String s, String open, String close) {
		String a = Text.before(s, open);
		if (a == null)
			return s;
		String b = Text.after(Text.after(s, open), close);
		if (b == null)
			return s;
		return a + b;
	}

	public static final String removeAllInner(String s, String open, String close) {
		while (true) {
			String replaced = Text.removeInnerIfAny(s, open, close);
			if (replaced == s)
				break;
			s = replaced;
		}
		return s;
	}

	public static final String removeAllOuter(String s, String open, String close) {
		while (true) {
			String replaced = Text.removeOuterIfAny(s, open, close);
			if (replaced == s)
				break;
			s = replaced;
		}
		return s;
	}

	public static final String remove(String s, char c) {
		int count = Text.count(s, c);
		if (count == 0)
			return s;

		char[] curr = s.toCharArray();
		char[] next = new char[curr.length - count];

		for (int i = 0, j = 0; i < curr.length; i++)
			if (curr[i] != c)
				next[j++] = curr[i];

		return new String(next);
	}

	public static final String remove(String s, char... cs) {
		int count = 0;
		for (char c : cs)
			count += Text.count(s, c);
		if (count == 0)
			return s;

		char[] curr = s.toCharArray();
		char[] next = new char[curr.length - count];

		outer: for (int i = 0, j = 0; i < curr.length; i++) {
			for (int k = 0; k < cs.length; k++)
				if (curr[i] == cs[k])
					continue outer;

			next[j++] = curr[i];
		}

		return new String(next);
	}

	public static final String remove(String s, String find) {
		return Text.replace(s, find, "");
	}

	public static final String convertWhiteSpaceTo(String s, char c) {
		char[] cs = s.toCharArray();
		for (int i = 0; i < cs.length; i++)
			if (cs[i] <= ' ')
				cs[i] = c;
		return new String(cs);
	}

	//

	public static final int indexOfWhiteSpace(String s) {
		for (int i = 0; i < s.length(); i++)
			if (s.charAt(i) <= ' ')
				return i;
		return -1;
	}

	public static final int lastIndexOfWhiteSpace(String s) {
		for (int i = s.length() - 1; i >= 0; i--)
			if (s.charAt(i) <= ' ')
				return i;
		return -1;
	}

	public static final String[] splitOnWhiteSpace(String s) {
		s = Text.convertWhiteSpaceTo(s, ' ');
		s = Text.removeDuplicates(s, ' ');
		return Text.split(s, ' ');
	}

	public static final String[] splitPairOnWhiteSpace(String s) {
		s = Text.convertWhiteSpaceTo(s, ' ');
		s = Text.removeDuplicates(s, ' ');
		return Text.splitPair(s, ' ');
	}

	public static final String trimBefore(String s) {
		for (int i = 0; i < s.length(); i++)
			if (s.charAt(i) > ' ')
				return s.substring(i);
		return "";
	}

	public static final String removeDuplicates(String s, char c) {
		if (s.indexOf(c) == -1)
			return s; // early escape
		if (s.indexOf(c) == s.lastIndexOf(c))
			return s; // early escape

		char[] array = s.toCharArray();

		StringBuilder buffer = new StringBuilder();

		boolean duplicate = false;

		for (int i = 0; i < array.length; i++) {
			if (array[i] != c) {
				buffer.append(array[i]);
				duplicate = false;
				continue;
			}

			if (duplicate)
				continue;

			buffer.append(array[i]);
			duplicate = true;
		}

		return buffer.toString();
	}

	/**
	 * CONTAINS
	 */

	public static final boolean contains(String[] array, String search) {
		if (search == null) {
			for (String s : array)
				if (s == null)
					return true;
		} else {
			for (String s : array)
				if (search.equals(s))
					return true;
		}

		return false;
	}

	/**
	 * CAPITALIZE
	 */

	public static final String capitalize(String value) {
		if (value.length() == 0)
			return value;

		if (value.length() == 1)
			return value.toUpperCase();

		return value.substring(0, 1).toUpperCase() + value.substring(1);
	}

	public static final String decapitalize(String value) {
		if (value.length() == 0)
			return value;

		if (value.length() == 1)
			return value.toLowerCase();

		return value.substring(0, 1).toLowerCase() + value.substring(1);
	}

	/**
	 * ARGS
	 */

	public static final Map<String, String> parseProperties(String value) {
		Map<String, String> map = new HashMap<String, String>();

		String[] lines = Text.splitOnLines(value);

		for (String line : lines) {
			line = Text.beforeIfAny(line, '#');
			line = line.trim();
			if (line.length() == 0)
				continue;

			String[] pair = Text.splitPair(line, '=');
			if (pair == null)
				continue;

			String key = pair[0].trim();
			String val = pair[1].trim();

			map.put(key, val);
		}

		return map;
	}

	public static final Map<String, String> parseArgs(String value, String sep, String split) {
		String[] pairs = Text.split(value, sep);
		String[] part = new String[2];

		Map<String, String> map = new HashMap<String, String>();

		for (String pair : pairs) {
			if (!pair.contains(String.valueOf(split)))
				continue;

			Text.splitPair(pair, split, part);
			map.put(part[0], part[1]);
		}

		return map;
	}

	public static final Map<String, String> parseArgs(String value, char sep, char split) {
		String[] pairs = Text.split(value, sep);
		String[] pair = new String[2];

		Map<String, String> map = new HashMap<String, String>();

		for (String p : pairs) {
			if (Text.splitPair(p, split, pair) == null)
				map.put(p, "");
			else
				map.put(pair[0], pair[1]);
		}

		return map;
	}

	public static final String joinArgs(Map<String, String> map, String sep, String split) {
		StringBuilder sb = new StringBuilder();

		for (String key : map.keySet()) {
			sb.append(key);
			sb.append(split);
			sb.append(map.get(key));
			sb.append(sep);
		}

		if (sb.length() > 0) {
			sb.setLength(sb.length() - 1);
		}

		return sb.toString();
	}

	public static final String joinArgs(Map<String, String> map, char sep, char split) {
		StringBuilder sb = new StringBuilder();

		for (String key : map.keySet()) {
			sb.append(key);
			sb.append(split);
			sb.append(map.get(key));
			sb.append(sep);
		}

		if (sb.length() > 0) {
			sb.setLength(sb.length() - 1);
		}

		return sb.toString();
	}

	/**
	 * DECODE URL
	 */

	public static final String decodeURL(String encoded, String charset) {
		return Text.decodeURL(encoded, charset, true);
	}

	public static final String decodeURL(String encoded, String charset, boolean decodePlus) {
		if (decodePlus) {
			encoded = Text.replace(encoded, '+', ' ');
		}

		StringBuilder chars = new StringBuilder();
		ByteList hex = new ByteList();
		Charset decoder = Charset.forName(charset);

		String[] parts = Text.split(encoded, '%');
		for (int i = 0; i < parts.length; i++) {
			String part = parts[i];
			if (i == 0)
				chars.append(part);
			else if (part.isEmpty())
				continue;
			else if (part.startsWith("u")) {
				if (hex.size() > 0) {
					chars.append(decoder.decode(ByteBuffer.wrap(hex.toArray())).toString());
					hex.clear();
				}

				try {
					int unicode = 0;
					unicode |= chr2oct(part.charAt(1)) << 12;
					unicode |= chr2oct(part.charAt(2)) << 8;
					unicode |= chr2oct(part.charAt(3)) << 4;
					unicode |= chr2oct(part.charAt(4)) << 0;
					chars.append((char) unicode);
					chars.append(part.substring(5));
				} catch (IllegalStateException exc) {
					chars.append(part);
				}
			} else {
				try {
					int unicode = 0;
					unicode |= chr2oct(part.charAt(0)) << 4;
					unicode |= chr2oct(part.charAt(1)) << 0;
					hex.add((byte) unicode);
					if (part.length() == 2)
						continue;
				} catch (IllegalStateException exc) {
					chars.append(part);
				}

				if (hex.size() > 0) {
					chars.append(Charset.forName(charset).decode(ByteBuffer.wrap(hex.toArray())).toString());
					hex.clear();
				}
				chars.append(part.substring(2));
			}
		}

		if (hex.size() > 0) {
			chars.append(Charset.forName(charset).decode(ByteBuffer.wrap(hex.toArray())).toString());
			hex.clear();
		}

		return chars.toString();
	}

	private static int chr2oct(char c) {
		if (c >= '0' && c <= '9')
			return c - '0';
		if (c >= 'a' && c <= 'f')
			return 10 + c - 'a';
		if (c >= 'A' && c <= 'F')
			return 10 + c - 'A';
		throw new IllegalStateException();
	}

	/**
    * 
    */

	public static final void mainArgsLookup(String[] args, Map<String, String> params) {
		for (String key : params.keySet()) {
			String val = Text.mainArgsLookup(args, key);

			if (val == null) {
				if (params.get(key) == null)
					throw new IllegalStateException("parameter for -" + key + " not found, and no default value");
			} else {
				params.put(key, val);
			}
		}
	}

	public static final String mainArgsLookup(String[] args, String key) {
		return Text.mainArgsLookup(args, key, null);
	}

	public static final String mainArgsLookup(String[] args, String key, String def) {
		return Text.mainArgsLookup(args, key, def, 0);
	}

	public static final List<String> mainArgsLookups(String[] args, String key) {
		key = "-" + key;

		List<String> matches = new ArrayList<String>();
		for (int i = 0; i < args.length - 1; i++)
			if (args[i].equals(key))
				matches.add(args[i += 1]);
		return matches;
	}

	public static final String mainArgsLookup(String[] args, String key, String def, int skip) {
		key = "-" + key;

		for (int i = 0; i < args.length - 1; i++)
			if (args[i].equals(key) && (skip-- == 0))
				return args[i + 1];
		return def;
	}

	public static boolean areCharsAt(String s, char c, int off1, int off2) {
		if (s.charAt(off1) == c)
			if (s.charAt(off2) == c)
				return true;
		return false;
	}

	public static boolean areDigits(String s, int off, int len) {
		int end = off + len;
		for (int i = off; i < end; i++)
			if (s.charAt(i) < '0' || s.charAt(i) > '9')
				return false;
		return true;
	}

	/**
	 * ROMAN
	 */

	public static final String rot13(String input) {
		char[] out = input.toCharArray();
		int i = 0;
		for (char c : out) {
			if (c >= 'a' && c <= 'z') {
				c -= 'a';
				c += 13;
				c %= 26;
				c += 'a';
			} else if (c >= 'A' && c <= 'Z') {
				c -= 'A';
				c += 13;
				c %= 26;
				c += 'A';
			} else if (c >= '0' && c <= '9') {
				c -= '0';
				c += 5;
				c %= 10;
				c += '0';
			}
			out[i++] = c;
		}
		return new String(out);
	}

	public static String traverse(String input, String[] delimiters, int[] maxLengths, TextTransformer transformer) {
		if (maxLengths.length + 1 != delimiters.length)
			throw new IllegalStateException();
		String[] matches = new String[maxLengths.length];

		StringBuilder rewritten = null;

		int offset = 0;

		outer: while (!input.isEmpty()) {
			int[] ios = new int[delimiters.length];

			for (int i = 0; i < delimiters.length; i++) {
				int off = (i == 0) ? offset : (ios[i - 1] + delimiters[i - 1].length());
				ios[i] = input.indexOf(delimiters[i], off);
				if (ios[i] == -1) {
					// not found
					break outer;
				}

				if (i == 0) {
					continue;
				}

				String ps = delimiters[i - 1];
				int pio = ios[i - 1];

				// too long?
				int len = (ios[i] - pio) - ps.length();
				if (len > maxLengths[i - 1]) {
					// advance
					offset = ios[0] + 1;
					continue outer;
				}

				matches[i - 1] = input.substring(pio + ps.length(), ios[i]);
			}

			// match!

			if (rewritten == null)
				rewritten = new StringBuilder();

			// merge!
			String[] merged = new String[(matches.length << 1) + 1];
			for (int i = 0; i < merged.length; i++)
				merged[i] = ((i & 1) == 0) ? delimiters[i >> 1] : matches[i >> 1];
			transformer.transform(merged);

			rewritten.append(input.substring(0, ios[0]));
			rewritten.append(join(merged));
			input = input.substring(ios[ios.length - 1] + delimiters[ios.length - 1].length());
			offset = 0;
		}

		if (rewritten != null) {
			input = rewritten.append(input).toString();
		}

		return input;
	}
}