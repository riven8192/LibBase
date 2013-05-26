package craterstudio.bytes;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class Checksum
{
   /**
    * UTILITY
    */

   public static final byte[] hash(byte[] data)
   {
      Checksum c = new Checksum();
      c.update(data, 0, data.length);

      //

      byte[] hash = new byte[16];
      c.crcfinal(hash);
      return hash;
   }

   public static final byte[] hash(byte[] data0, byte[] data1)
   {
      Checksum c = new Checksum();
      c.update(data0);
      c.update(data1);

      byte[] hash = new byte[16];
      c.crcfinal(hash);
      return hash;
   }

   public static final byte[] hash(File file)
   {
      Checksum c = new Checksum();

      try
      {
         byte[] buf = new byte[64 * 1024];
         int filled = 0;

         InputStream in = new FileInputStream(file);
         while ((filled = in.read(buf)) != -1)
            c.update(buf, 0, filled);
         in.close();
      }
      catch (IOException exc)
      {
         return null;
      }

      byte[] hash = new byte[16];
      c.crcfinal(hash);
      return hash;
   }

   /**
    * 
    */

   private int[] checksum = new int[4];
   private int   lastByte;

   public void update(byte[] buf)
   {
      this.update(buf, 0, buf.length);
   }

   public void update(byte[] buf, int len)
   {
      this.update(buf, 0, len);
   }

   public void update(byte[] buf, int off, int len)
   {
      int end = off + len;

      int s;
      int b = lastByte;
      int[] c = checksum;

      for (int i = off; i < end; i++)
      {
         s = b & 0x1F;
         b = buf[i] & 0xFF;
         c[(b | s) & 0x03] ^= b << s;
      }

      lastByte = b;
   }

   public void crcfinal(byte[] result)
   {
      for (int i = 0; i < 16; i++)
         result[i] = (byte) (checksum[i >> 2] >>> ((i & 3) * 8));
   }
}