/*
 * Created on Apr 5, 2010
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;

public class BytePatternReplacer extends BytePatternMatcher
{
   private final byte[] replacement;

   public BytePatternReplacer(byte[] search, byte[] replacement)
   {
      super(search);

      this.replacement = replacement.clone();
   }

   protected void onPattern(OutputStream out, byte[] pattern, int off, int len) throws IOException
   {
      out.write(this.replacement);
   }
}
