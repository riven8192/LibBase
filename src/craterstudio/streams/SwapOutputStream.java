/*
 * Created on 20 aug 2010
 */

package craterstudio.streams;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import craterstudio.io.Streams;

public abstract class SwapOutputStream extends AbstractOutputStream
{
   private long               rem;
   private OutputStream       swap;
   private final OutputStream target;

   public SwapOutputStream(long maxBytes, OutputStream after)
   {
      super(new ByteArrayOutputStream());

      this.rem = maxBytes;
      this.swap = null;
      this.target = after;
   }

   //

   protected abstract File provideSwapFile() throws IOException;

   private File swapFile;

   //

   private OutputStream provideSwapOutputStream() throws IOException
   {
      if (this.swapFile != null)
         throw new IllegalStateException();
      this.swapFile = this.provideSwapFile();
      return new BufferedOutputStream(new FileOutputStream(this.swapFile));
   }

   private void switchStreams() throws IOException
   {
      if (this.swap != null)
         throw new IllegalStateException();
      this.swap = this.provideSwapOutputStream();
      if (this.swap == null)
         throw new NullPointerException();
      ((ByteArrayOutputStream) super.backing).writeTo(this.swap);
   }

   //

   @Override
   public void write(byte[] buf, int off, int len) throws IOException
   {
      if (this.swap == null && len > this.rem)
         this.switchStreams();

      if (this.swap == null)
         this.rem -= len;

      ((this.swap != null) ? this.swap : super.backing).write(buf, off, len);
   }

   @Override
   public void flush() throws IOException
   {
      ((this.swap != null) ? this.swap : super.backing).flush();
   }

   @Override
   public void close() throws IOException
   {
      ((this.swap != null) ? this.swap : super.backing).close();

      if (this.swap == null)
      {
         ((ByteArrayOutputStream) super.backing).writeTo(this.target);
         this.target.close();
      }
      else
      {
         Streams.pump(new FileInputStream(this.swapFile), this.target);

         this.swapFile.delete();
      }
   }
}
