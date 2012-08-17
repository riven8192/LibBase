/*
 * Created on 6-feb-2006
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.InputStream;

public class CountingInputStream extends InputStream
{
   private final InputStream in;
   private long              bytes;

   public CountingInputStream(InputStream in)
   {
      this.in = in;
      this.bytes = 0;
   }

   public long bytes()
   {
      return this.bytes;
   }

   @Override
   public int read() throws IOException
   {
      int b = this.in.read();
      if (b == -1)
         return -1;
      this.bytes += 1;
      return b;
   }

   @Override
   public int read(byte[] buf) throws IOException
   {
      return this.read(buf, 0, buf.length);
   }

   @Override
   public int read(byte[] buf, int off, int len) throws IOException
   {
      int b = this.in.read(buf, off, len);
      if (b == -1)
         return -1;
      this.bytes += b;
      return b;
   }

   @Override
   public void close() throws IOException
   {
      this.in.close();
   }
}
