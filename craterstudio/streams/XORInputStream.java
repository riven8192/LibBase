/*
 * Created on 10 aug 2010
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.InputStream;

import craterstudio.bytes.XOR;

public class XORInputStream extends AbstractInputStream
{
   private final byte[] key;
   private int          pos;

   public XORInputStream(InputStream out, byte[] key)
   {
      super(out);
      this.key = key;
      this.pos = 0;
   }

   @Override
   public int read(byte[] buf, int off, int len) throws IOException
   {
      XOR.xor(buf, off, len, this.key, this.pos);
      int got = super.read(buf, off, len);
      if (got == -1)
         return -1;
      this.pos += len;
      return got;
   }
}