/*
 * Created on 8 okt 2008
 */

package craterstudio.util;

import java.nio.Buffer;
import java.nio.ByteBuffer;

public class ByteBufferUtil
{
   public static String bufferToAscii(ByteBuffer buf)
   {
      int off = buf.position();
      char[] headerText = new char[buf.remaining()];
      for (int i = 0; i < headerText.length; i++)
         headerText[i] = (char) (buf.get(off + i) & 0xFF);
      buf.position(buf.limit());
      return new String(headerText);
   }

   public static void asciiToBuffer(String str, ByteBuffer buf)
   {
      if (str.length() != buf.remaining())
         throw new IllegalStateException();

      int off = buf.position();
      int len = str.length();
      for (int i = 0; i < len; i++)
         buf.put(off + i, (byte) str.charAt(i));
      buf.position(buf.position() + len);
   }

   public static Buffer setup(Buffer buf, int pos, int lim)
   {
      buf.limit(lim);
      buf.position(pos);
      return buf;
   }

   public static Buffer setRemaining(Buffer buf, int rem)
   {
      buf.limit(buf.position() + rem);
      return buf;
   }

   public static Buffer flipForward(Buffer buf)
   {
      buf.position(buf.limit());
      buf.limit(buf.capacity());
      return buf;
   }

   public static ByteBuffer compactSelect(ByteBuffer buf)
   {
      int rem = buf.remaining();
      buf.compact();

      buf.position(0);
      buf.limit(rem);
      return buf;
   }

   public static void get(ByteBuffer src, int bytes, ByteBuffer dst)
   {
      int lim = src.limit();
      src.limit(src.position() + bytes);
      dst.put(src);
      src.limit(lim);
   }
}
