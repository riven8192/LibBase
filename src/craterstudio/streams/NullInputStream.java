/*
 * Created on 15-sep-2006
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.InputStream;

public class NullInputStream extends InputStream
{
   private final InputStream in;

   public NullInputStream()
   {
      this(null);
   }

   public NullInputStream(InputStream in)
   {
      this.in = in;
   }

   @Override
   public int read() throws IOException
   {
      return -1;
   }

   @Override
   public int available() throws IOException
   {
      return 0;
   }

   @Override
   public void close() throws IOException
   {
      if (this.in != null)
      {
         in.close();
      }
   }
}
