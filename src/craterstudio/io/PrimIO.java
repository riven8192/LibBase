package craterstudio.io;

import java.nio.ByteBuffer;

public class PrimIO
{
   public static final long swap64(long v)
   {
      long r = 0;
      r |= ((v >> 0) & 0xFF) << 56;
      r |= ((v >> 8) & 0xFF) << 48;
      r |= ((v >> 16) & 0xFF) << 40;
      r |= ((v >> 24) & 0xFF) << 32;
      r |= ((v >> 32) & 0xFF) << 24;
      r |= ((v >> 40) & 0xFF) << 16;
      r |= ((v >> 48) & 0xFF) << 8;
      r |= ((v >> 56) & 0xFF) << 0;
      return r;
   }

   public static final int swap32(int v)
   {
      int r = 0;
      r |= ((v >> 0) & 0xFF) << 24;
      r |= ((v >> 8) & 0xFF) << 16;
      r |= ((v >> 16) & 0xFF) << 8;
      r |= ((v >> 24) & 0xFF) << 0;
      return r;
   }

   public static final int swap16(int v)
   {
      int r = 0;
      r |= ((v >> 0) & 0xFF) << 8;
      r |= ((v >> 8) & 0xFF) << 0;
      return r;
   }

   /**
    * SHORT
    */

   public static final byte readByte(byte[] buf)
   {
      return readByte(buf, 0);
   }

   public static final byte readByte(byte[] buf, int off)
   {
      return buf[off];
   }

   public static final void writeByte(byte[] buf, byte val)
   {
      writeByte(buf, 0, val);
   }

   public static final void writeByte(byte[] buf, int off, byte val)
   {
      buf[off] = val;
   }

   /**
    * SHORT
    */

   public static final short readShort(byte[] buf)
   {
      return readShort(buf, 0);
   }

   public static final short readShort(byte[] buf, int off)
   {
      short val = 0;

      val |= (buf[off + 0] & 0xFF) << 8;
      val |= (buf[off + 1] & 0xFF) << 0;

      return val;
   }

   public static final void writeShort(byte[] buf, short val)
   {
      writeShort(buf, 0, val);
   }

   public static final void writeShort(byte[] buf, int off, short val)
   {
      buf[off + 0] = (byte) (val >> 8);
      buf[off + 1] = (byte) (val >> 0);
   }

   /**
    * INT
    */

   public static final int readInt(byte[] buf)
   {
      return readInt(buf, 0);
   }

   public static final int readInt(byte[] buf, int off)
   {
      int val = 0;

      val |= (buf[off + 0] & 0xFF) << 24;
      val |= (buf[off + 1] & 0xFF) << 16;
      val |= (buf[off + 2] & 0xFF) << 8;
      val |= (buf[off + 3] & 0xFF) << 0;

      return val;
   }

   public static final int writeInt(byte[] buf, int val)
   {
      return writeInt(buf, 0, val);
   }

   public static final int writeInt(byte[] buf, int off, int val)
   {
      buf[off + 0] = (byte) (val >> 24);
      buf[off + 1] = (byte) (val >> 16);
      buf[off + 2] = (byte) (val >> 8);
      buf[off + 3] = (byte) (val >> 0);

      return off + 4;
   }

   /**
    * LONG
    */

   public static final long readLong(byte[] buf)
   {
      return readLong(buf, 0);
   }

   public static final long readLong(byte[] buf, int off)
   {
      long val = 0;

      val |= (long) (buf[off + 0] & 0xFF) << 56;
      val |= (long) (buf[off + 1] & 0xFF) << 48;
      val |= (long) (buf[off + 2] & 0xFF) << 40;
      val |= (long) (buf[off + 3] & 0xFF) << 32;
      val |= (long) (buf[off + 4] & 0xFF) << 24;
      val |= (long) (buf[off + 5] & 0xFF) << 16;
      val |= (long) (buf[off + 6] & 0xFF) << 8;
      val |= (long) (buf[off + 7] & 0xFF) << 0;

      return val;
   }

   public static final int writeLong(byte[] buf, long val)
   {
      return writeLong(buf, 0, val);
   }

   public static final int writeLong(byte[] buf, int off, long val)
   {
      buf[off + 0] = (byte) ((val >> 56) & 0xFF);
      buf[off + 1] = (byte) ((val >> 48) & 0xFF);
      buf[off + 2] = (byte) ((val >> 40) & 0xFF);
      buf[off + 3] = (byte) ((val >> 32) & 0xFF);
      buf[off + 4] = (byte) ((val >> 24) & 0xFF);
      buf[off + 5] = (byte) ((val >> 16) & 0xFF);
      buf[off + 6] = (byte) ((val >> 8) & 0xFF);
      buf[off + 7] = (byte) ((val >> 0) & 0xFF);

      return off + 8;
   }

   /**
    * STRING
    */

   public static final String readString(byte[] buf, int off, int max)
   {
      int last = -1;

      for (int i = 0; i < max; i++)
      {
         if (buf[off + i] == (byte) 0x00)
         {
            last = i;
            break;
         }
      }

      if (last == -1)
         last = max;

      char[] c = new char[last];
      for (int i = 0; i < c.length; i++)
         c[i] = (char) (buf[off + i] & 0xFF);

      return new String(c);
   }

   public static final int writeString(byte[] buf, int off, int max, String str)
   {
      if (str.length() > max)
         throw new IllegalArgumentException();

      for (int i = 0; i < str.length(); i++)
         buf[off + i] = (byte) (str.charAt(i) & 0xFF);

      if (str.length() != max)
         buf[off + str.length()] = (byte) 0x00;

      return off + max;
   }

   //

   public static final String readStringFromBuffer(ByteBuffer buf, int total)
   {
      int len = buf.getInt();

      if (len > 65536)
         throw new IllegalStateException("corrupt string length: " + len);

      char[] c = new char[len];
      for (int i = 0; i < c.length; i++)
         c[i] = buf.getChar();

      int rem = total - len - 4;
      for (int i = 0; i < rem; i++)
         buf.getChar();

      return new String(c);
   }

   public static final void writeStringToBuffer(ByteBuffer buf, String str, int total)
   {
      if (str.length() + 4 > total)
         throw new IllegalStateException();

      buf.putInt(str.length());
      for (int i = 0; i < str.length(); i++)
         buf.putChar(str.charAt(i));

      int rem = total - str.length() - 4;
      for (int i = 0; i < rem; i++)
         buf.putChar((char) 0x0000);
   }
}
