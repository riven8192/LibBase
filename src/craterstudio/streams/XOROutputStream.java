/*
 * Created on 10 aug 2010
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;

import craterstudio.bytes.XOR;

public class XOROutputStream extends AbstractOutputStream
{
   private final byte[] key;
   private int          pos;

   public XOROutputStream(OutputStream out, byte[] key)
   {
      super(out);
      this.key = key;
      this.pos = 0;
   }

   @Override
   public void write(byte[] buf, int off, int len) throws IOException
   {
      XOR.xor(buf, off, len, this.key, this.pos);
      super.write(buf, off, len);
      this.pos += len;
   }
}