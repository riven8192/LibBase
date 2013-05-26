/*
 * Created on Sep 18, 2011
 */

package craterstudio.text;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexUtil {
	public static interface RegexCallback {
		public String replace(String input, Matcher matcher);
	}

	public static String getMatchRegion(String input, Matcher matcher) {
		return input.substring(matcher.start(), matcher.end());
	}

	public static String getMatchRegion(String input, Matcher matcher, int index) {
		return input.substring(matcher.start(index), matcher.end(index));
	}

	public static String replace(String input, Pattern pattern, RegexCallback callback) {
		Matcher m = pattern.matcher(input);
		int lastEnd = 0;
		StringBuilder build = new StringBuilder();
		while (m.find()) {
			build.append(input.substring(lastEnd, m.start()));
			String got = callback.replace(input, m);
			if (got == null)
				got = input.substring(m.start(), m.end());
			build.append(got);
			lastEnd = m.end();
		}
		build.append(input.substring(lastEnd));
		return build.toString();
	}

	public static String findFirst(String input, Pattern pattern, int index) {
		Matcher m = pattern.matcher(input);
		if (!m.find()) {
			return null;
		}
		return input.substring(m.start(index), m.end(index));
	}

	public static String[] find(String input, Pattern pattern, int... indices) {
		Matcher m = pattern.matcher(input);
		if (!m.find()) {
			return null;
		}

		String[] results = new String[indices.length];
		for (int i = 0; i < results.length; i++) {
			results[i] = input.substring(m.start(indices[i]), m.end(indices[i]));
		}
		return results;
	}
}
