/*
 * Created on Mar 26, 2008
 */

package craterstudio.streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import craterstudio.io.Streams;

public abstract class ChainedInputStream extends InputStream
{
   public static ChainedInputStream create(final InputStream... streams)
   {
      return new ChainedInputStream()
      {
         private int index = 0;

         @Override
         protected InputStream nextStream()
         {
            if (this.index < streams.length)
               return streams[this.index++];
            return null;
         }
      };
   }

   private InputStream currentStream;
   private boolean     reachedEndOfChain;

   public ChainedInputStream()
   {
      currentStream = null;
      reachedEndOfChain = false;
   }

   protected abstract InputStream nextStream();

   private final byte[] oneByteBuffer = new byte[1];

   @Override
   public int read() throws IOException
   {
      int r = this.read(oneByteBuffer);
      if (r == -1)
         return -1;
      return oneByteBuffer[0] & 0xFF;
   }

   @Override
   public int read(byte[] buf) throws IOException
   {
      return this.read(buf, 0, buf.length);
   }

   @Override
   public int read(byte[] buf, int off, int len) throws IOException
   {
      do
      {
         if (this.reachedEndOfChain)
         {
            return -1;
         }

         if (this.currentStream == null && (this.currentStream = this.nextStream()) == null)
         {
            this.reachedEndOfChain = true;
            return -1;
         }

         try
         {
            int got = this.currentStream.read(buf, off, len);
            if (got == -1)
               throw new EOFException();
            return got;
         }
         catch (IOException exc)
         {
            Streams.safeClose(this.currentStream);
            
            this.currentStream = null;
         }
      }
      while (true);
   }

   //

   @Override
   public boolean markSupported()
   {
      return false;
   }

   @Override
   public synchronized void mark(int bytes)
   {
      throw new UnsupportedOperationException();
   }

   @Override
   public synchronized void reset() throws IOException
   {
      throw new UnsupportedOperationException();
   }

   //

   @Override
   public int available() throws IOException
   {
      if (currentStream == null)
         return 0;
      return currentStream.available();
   }

   @Override
   public long skip(long n) throws IOException
   {
      if (currentStream == null)
         return 0;
      return currentStream.skip(n);
   }

   @Override
   public void close() throws IOException
   {
      Streams.safeClose(this.currentStream);
      this.currentStream = null;
      this.reachedEndOfChain = true;
   }
}