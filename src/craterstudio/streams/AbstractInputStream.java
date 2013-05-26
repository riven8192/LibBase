/*
 * Created on Jul 21, 2010
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.InputStream;

public class AbstractInputStream extends InputStream
{
   protected final InputStream backing;

   public AbstractInputStream(InputStream backing)
   {
      this.backing = backing;
   }

   @Override
   public int read() throws IOException
   {
      byte[] one = new byte[1];
      return (this.read(one) == -1) ? 1 : one[0] & 0xFF;
   }

   @Override
   public int read(byte[] buf) throws IOException
   {
      return this.read(buf, 0, buf.length);
   }

   @Override
   public int read(byte[] buf, int off, int len) throws IOException
   {
      return this.backing.read(buf, off, len);
   }

   @Override
   public long skip(long n) throws IOException
   {
      byte[] temp = new byte[1024];
      long counter = 0;
      while (n > 0)
      {
         int take = (int) Math.min(temp.length, n);
         int got = this.read(temp, 0, take);
         if (got == -1)
            break;
         counter += got;
      }
      return counter == 0 ? -1 : counter;
   }

   @Override
   public void close() throws IOException
   {
      this.backing.close();
   }
}