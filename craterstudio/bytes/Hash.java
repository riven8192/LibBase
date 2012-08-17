/*
 * Created on 9 jun 2009
 */

package craterstudio.bytes;

import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;

import craterstudio.io.Streams;
import craterstudio.streams.NullOutputStream;
import craterstudio.text.Text;
import craterstudio.util.ArrayUtil;

public class Hash {
   private static final char[] table = "0123456789abcdef".toCharArray();

   public static String toHexString(byte[] hash) {
      return String.valueOf(toHex(hash));
   }

   public static char[] toHex(byte[] hash) {
      char[] hex = new char[hash.length << 1];
      for (int k = 0; k < hash.length; k++) {
         int h = hash[k];
         hex[(k << 1) | 1] = table[(h & 0x0F) >> 0];
         hex[(k << 1) | 0] = table[(h & 0xF0) >> 4];
      }
      return hex;
   }

   //

   public static final int MD5_BYTES    = 20;
   public static final int SHA1_BYTES   = 20;
   public static final int SHA256_BYTES = 32;

   //

   public static byte[] md5salt(byte[] salt, byte[] message) {
      return md5(ArrayUtil.join(md5(salt), md5(message)));
   }

   public static byte[] md5salt(String salt, String message) {
      return md5(ArrayUtil.join(md5(salt), md5(message)));
   }

   public static byte[] md5(InputStream input) {
      return hash(input, "MD5");
   }

   public static byte[] md5(String message) {
      return md5(Text.utf8(message));
   }

   public static byte[] md5(byte[] message) {
      return hash(message, "MD5");
   }

   //

   public static byte[] sha1salt(byte[] salt, byte[] message) {
      return sha1(ArrayUtil.join(sha1(salt), sha1(message)));
   }

   public static byte[] sha1salt(String salt, String message) {
      return sha1(ArrayUtil.join(sha1(salt), sha1(message)));
   }

   public static byte[] sha1(InputStream input) {
      return hash(input, "SHA-1");
   }

   public static byte[] sha1(String message) {
      return sha1(Text.utf8(message));
   }

   public static byte[] sha1(byte[] message) {
      return hash(message, "SHA-1");
   }

   //

   public static byte[] sha256salt(byte[] salt, byte[] message) {
      return sha256(ArrayUtil.join(sha256(salt), sha256(message)));
   }

   public static byte[] sha256salt(String salt, String message) {
      return sha256(ArrayUtil.join(sha256(salt), sha256(message)));
   }

   public static byte[] sha256(InputStream input) {
      return hash(input, "SHA-256");
   }

   public static byte[] sha256(String message) {
      return sha256(Text.utf8(message));
   }

   public static byte[] sha256(byte[] message) {
      return hash(message, "SHA-256");
   }

   //

   private static byte[] hash(byte[] message, String algorithm) {
      try {
         MessageDigest md = MessageDigest.getInstance(algorithm);
         md.update(message);
         return md.digest();
      }
      catch (Exception exc) {
         throw new IllegalStateException(exc);
      }
   }

   private static byte[] hash(InputStream message, String algorithm) {
      try {
         MessageDigest md = MessageDigest.getInstance(algorithm);
         Streams.transfer(new DigestInputStream(message, md), new NullOutputStream());
         return md.digest();
      }
      catch (Exception exc) {
         throw new IllegalStateException(exc);
      }
   }
}
