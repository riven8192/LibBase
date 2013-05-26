/*
 * Created on 6-feb-2006
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;

public class CountingOutputStream extends OutputStream
{
   private final OutputStream out;
   private volatile long      bytes;

   public CountingOutputStream(OutputStream out)
   {
      this.out = out;
      this.bytes = 0;
   }

   public long bytes()
   {
      return this.bytes;
   }

   @Override
   public void write(int b) throws IOException
   {
      out.write(b);
      this.bytes++;
   }

   @Override
   public void write(byte[] buf) throws IOException
   {
      out.write(buf);
      this.bytes += buf.length;
   }

   @Override
   public void write(byte[] buf, int off, int len) throws IOException
   {
      out.write(buf, off, len);
      this.bytes += len;
   }

   @Override
   public void flush() throws IOException
   {
      out.flush();
   }

   @Override
   public void close() throws IOException
   {
      out.close();
   }
}
