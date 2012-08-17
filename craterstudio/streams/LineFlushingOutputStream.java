/*
 * Created on 6-feb-2006
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;

public class LineFlushingOutputStream extends LineEventOutputStream
{
   public LineFlushingOutputStream(OutputStream out)
   {
      super(out);
   }

   @Override
   protected void beforeLine(OutputStream out) throws IOException
   {
      out.flush();
   }

   @Override
   protected void afterLine(OutputStream out) throws IOException
   {
      out.flush();
   }
}
