package craterstudio.bytes;

import javax.xml.bind.DatatypeConverter;

import craterstudio.text.Text;

public class Base64 {

	public static byte[] decode(String b64) {
		if (b64.length() % 4 != 0) {
			throw new IllegalArgumentException("invalid base64 input");
		}
		return DatatypeConverter.parseBase64Binary(b64);
	}

	public static String encode(byte[] bin) {
		return DatatypeConverter.printBase64Binary(bin);
	}

	//

	public static byte[] decodeURL(String b64) {
		return decode(convertFromURL(b64));
	}

	public static String encodeURL(byte[] bin) {
		return convertToURL(encode(bin));
	}

	//

	private static final String convertFromURL(String b64) {
		b64 = b64.replace('-', '+').replace('_', '/');
		if (b64.length() % 4 == 1) {
			throw new IllegalStateException();
		}
		while (b64.length() % 4 != 0) {
			b64 += '=';
		}
		return b64;
	}

	private static final String convertToURL(String b64) {
		return Text.remove(b64.replace('+', '-').replace('/', '_'), '=');
	}
}