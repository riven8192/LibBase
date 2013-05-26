/*
 * Created on 23 okt 2008
 */

package craterstudio.text;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class URLAnalyzer {

	private static final int HTTP_LEN = 7;
	public static final String FAILURE = new String("");
	public static final String EMPTY = new String("");

	/**
	 * if any error occurs, the methods in this class return an empty String
	 */

	public static String getPrePath(String location) {
		int i = location.indexOf('/', HTTP_LEN);
		if (i == -1)
			return location;
		return location.substring(0, i);
	}

	// 7 == "http://".length();
	public static String getDomain(String location) {
		if (location.startsWith("file://"))
			return "localhost";

		// http://domainname.tld/
		// http://domainname.tld:80/
		// http://www.domainname.tld/
		// http://anything.domainname.tld/
		// http://anything.anything.domainname.tld/

		int i = location.indexOf('/', HTTP_LEN);
		if (i == -1)
			return FAILURE;

		String domain = location.substring(HTTP_LEN, i);

		// strip port
		if (domain.indexOf(':') != -1)
			domain = domain.substring(0, domain.indexOf(':'));

		// www.something.com./ is accepted/corrected by browsers
		if (domain.endsWith("."))
			domain = domain.substring(0, domain.length() - 1);

		int tldIndex = domain.lastIndexOf('.');
		if (tldIndex == -1)
			return FAILURE;

		String preTLD = domain.substring(0, tldIndex);
		int subIndex = preTLD.lastIndexOf('.');
		if (subIndex == -1)
			return domain.toLowerCase();

		// NAME.com.mx / NAME.co.uk
		String testDomain = domain.substring(subIndex + 1);
		if (testDomain.startsWith("com.") || testDomain.startsWith("co.")) {
			subIndex = preTLD.lastIndexOf('.', subIndex - 1);
			if (subIndex == -1)
				return domain.toLowerCase();
		}

		return domain.substring(subIndex + 1).toLowerCase();
	}

	public static String getSubdomain(String location) {
		String domain = URLAnalyzer.getDomain(location);

		if (domain == FAILURE)
			return FAILURE;

		String subWithDot = Text.before(location.substring(HTTP_LEN), domain);
		if (subWithDot == null || subWithDot.equals(""))
			return "www";
		return subWithDot.substring(0, subWithDot.length() - 1);
	}

	public static String getRequest(String location) {
		// http://whatever/.............

		int i = location.indexOf('/', HTTP_LEN);
		if (i == -1)
			return FAILURE;
		return location.substring(i);
	}

	private static final char[] ca = new char[] { '?', '&', '#' };

	public static String getPath(String location) {
		// http://whatever/...............{{?|&|#}anything}

		int minIndex = location.length();
		for (int i = 0; i < ca.length; i++) {
			int index = location.indexOf(ca[i]);
			if (index != -1 && index < minIndex)
				minIndex = index;
		}

		int i = location.indexOf('/', HTTP_LEN);
		if (i == -1)
			return FAILURE;

		return location.substring(i, minIndex);
	}

	public static String getQuery(String location) {
		// http://whatever/xyz/abc{?|&}.............{#anything}

		int offQ = location.indexOf('?');
		int offA = location.indexOf('&');

		if (offQ == offA) // both -1
			return EMPTY;

		int off;
		if (offQ == -1)
			off = offA;
		else if (offA == -1)
			off = offQ;
		else
			off = Math.min(offQ, offA);

		int offH = location.indexOf('#');
		if (offH < off)
			offH = -1;
		int end = (offH != -1) ? offH : location.length();

		try {
			return location.substring(off + 1, end);
		} catch (StringIndexOutOfBoundsException exc) {
			System.err.println("NO QUERY FOR: =" + location);
			return location;
		}
	}

	public static String findParam(String location, String key) {
		String q = URLAnalyzer.getQuery(location);
		String find = key + '=';

		if (q.contains(find))
			for (String part : Text.split(q, '&'))
				if (part.startsWith(find))
					return Text.after(part, find);
		return "";
	}

	public static boolean hasParam(String location, String key) {
		return !URLAnalyzer.findParam(location, key).equals("");
	}

	public static boolean hasParam(String location, String key, String value) {
		return URLAnalyzer.findParam(location, key).equals(value);
	}

	public static String getAnchor(String location) {
		// http://whatever/xyz/abc{anything}{#}.............

		int off = location.indexOf('#');
		if (off == -1)
			return EMPTY;
		return location.substring(off + 1);
	}

	public static String removeAnchor(String location) {
		int off = location.indexOf('#');
		if (off == -1)
			return location;
		return location.substring(0, off);
	}

	public static String withNormalizedDomain(String location) {
		int i = location.indexOf('/', HTTP_LEN);
		if (i == -1)
			return FAILURE;

		String sub = URLAnalyzer.getSubdomain(location);
		String domain = URLAnalyzer.getDomain(location);

		return "http://" + sub + "." + domain + URLAnalyzer.getRequest(location);
	}

	public static String removeParam(String location, String key) {
		String find = key + '=';
		if (!location.contains(find))
			return location;

		String prepath = URLAnalyzer.getPrePath(location);
		String path = URLAnalyzer.getPath(location);
		String query = URLAnalyzer.getQuery(location);
		String anchor = URLAnalyzer.getAnchor(location);

		List<String> otherParams = new ArrayList<String>();
		for (String part : Text.split(query, '&'))
			if (!part.startsWith(find))
				otherParams.add(part);
		query = Text.join(otherParams.toArray(new String[otherParams.size()]), '&');

		String rebuild = prepath + path;

		if (query.length() != 0)
			rebuild += "?" + query;
		if (anchor.length() != 0)
			rebuild += "#" + anchor;

		return rebuild;
	}
}
