/*
 * Created on 23 mei 2011
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;

public class DelayedGZipInputStream extends AbstractInputStream
{
   public DelayedGZipInputStream(final InputStream in)
   {
      super(new ChainedInputStream()
      {
         boolean first = true;

         @Override
         protected InputStream nextStream()
         {
            if (!this.first)
            {
               return null;
            }

            this.first = false;

            try
            {
               return new GZIPInputStream(in);
            }
            catch (IOException exc)
            {
               throw new IllegalStateException(exc);
            }
         }
      });
   }

}
