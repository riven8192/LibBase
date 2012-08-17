/*
 * Created on 4 jun 2010
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.InputStream;

import craterstudio.io.Streams;

public class HttpChunkedInputStream extends InputStream
{
   private static final int  INACTIVE = -1;

   private final InputStream in;

   public HttpChunkedInputStream(InputStream in)
   {
      this.in = in;
      this.oneByte = new byte[1];
      this.chunkSize = -1;
      this.remaining = 0;
   }

   private final byte[] oneByte;
   private int          chunkSize;
   private int          remaining;

   private int readNextChunk()
   {
      String line = Streams.binaryReadLineAsString(this.in);
      int chunkSize = Integer.parseInt(line.trim(), 16);
      if (chunkSize < 0)
         throw new IllegalStateException("chunked transfer encoding corrupted");
      return chunkSize;
   }

   @Override
   public int read() throws IOException
   {
      int got = this.read(this.oneByte);
      return (got == -1) ? -1 : (oneByte[0] & 0xFF);
   }

   @Override
   public int read(byte[] buf) throws IOException
   {
      return this.read(buf, 0, buf.length);
   }

   @Override
   public int read(byte[] buf, int off, int len) throws IOException
   {
      if (this.chunkSize == 0)
      {
         return -1;
      }

      if (this.chunkSize == INACTIVE || this.remaining == 0)
      {
         this.chunkSize = this.readNextChunk();
         if (this.chunkSize == 0)
            return -1;
         this.remaining = this.chunkSize;
      }

      len = Math.min(this.remaining, len);
      if (len == 0)
         throw new IllegalStateException("chunked transfer encoding corrupted");
      int got = this.in.read(buf, off, len);
      if (got == 0)
         throw new IllegalStateException("chunked transfer encoding corrupted");
      if (got == -1)
         return -1;

      this.remaining -= got;
      if (this.remaining < 0)
         throw new IllegalStateException();

      if (this.remaining == 0 && !Streams.binaryReadLineAsString(this.in).equals(""))
         throw new IllegalStateException("chunked transfer encoding corrupted");

      return got;
   }

   @Override
   public void close() throws IOException
   {
      try
      {
         this.verifyEndState();
      }
      // catch (IllegalStateException exc)
      // {
      // System.err.println(this.getClass().getSimpleName() + ".verifyEndState() failed: " + exc.getMessage());
      // }
      finally
      {
         this.in.close();
      }
   }

   //

   public void verifyEndState()
   {
      if (this.chunkSize == INACTIVE)
      {
         return;
      }

      if (this.chunkSize != 0)
      {
         if (this.remaining != 0)
            throw new IllegalStateException("chunk active:" + this.remaining + " bytes remaining");

         this.chunkSize = this.readNextChunk();
         if (this.chunkSize != 0)
            throw new IllegalStateException("next chunk pending: " + this.chunkSize + " bytes");
      }

      if (!Streams.binaryReadLineAsString(this.in).isEmpty())
         throw new IllegalStateException("chunked transfer encoding corrupted");
      this.chunkSize = INACTIVE;
   }

   //

   public long skip(long n) throws IOException
   {
      if (n < 0)
         throw new IllegalArgumentException();
      if (n == 0)
         return 0;

      byte[] buf = new byte[1024];

      long skipped = 0;
      while (n > 0)
      {
         int got = this.read(buf);
         if (got == -1)
            return skipped;
         skipped += got;
      }
      return skipped;
   }

   @Override
   public int available() throws IOException
   {
      return this.remaining;
   }

   @Override
   public synchronized void reset() throws IOException
   {
      throw new UnsupportedOperationException();
   }

   @Override
   public synchronized void mark(int readlimit)
   {
      throw new UnsupportedOperationException();
   }

   @Override
   public boolean markSupported()
   {
      return false;
   }
}