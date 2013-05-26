/*
 * Created on 24 jan 2008
 */

package craterstudio.bytes;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Adler32;

import craterstudio.io.Streams;

public class CRC
{
   public static final int createChecksum(File file)
   {
      try
      {
         if (file.isDirectory())
            return -1;
         return CRC.createChecksum(new FileInputStream(file));
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public static final int createChecksum(InputStream in)
   {
      try
      {
         Adler32 adler = new Adler32();

         byte[] buf = new byte[1024];
         while (true)
         {
            int b = in.read(buf, 0, buf.length);
            if (b == -1)
               break;
            adler.update(buf, 0, b);
         }

         Streams.safeClose(in);

         return (int) (adler.getValue() & 0xFFFFFFFF);
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }
   }
}
