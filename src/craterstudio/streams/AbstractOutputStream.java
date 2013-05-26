/*
 * Created on Jul 21, 2010
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;

public class AbstractOutputStream extends OutputStream {
   protected OutputStream backing;

   public AbstractOutputStream(OutputStream backing) {
      this.backing = backing;
   }

   @Override
   public void write(int b) throws IOException {
      byte[] one = new byte[1];
      one[0] = (byte) b;
      this.write(one, 0, one.length);
   }

   @Override
   public void write(byte[] b) throws IOException {
      this.write(b, 0, b.length);
   }

   @Override
   public void write(byte[] b, int off, int len) throws IOException {
      this.backing.write(b, off, len);
   }

   @Override
   public void flush() throws IOException {
      this.backing.flush();
   }

   @Override
   public void close() throws IOException {
      this.backing.close();
   }
}
