/*
 * Created on Apr 5, 2010
 */

package craterstudio.streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import craterstudio.io.Streams;

public abstract class StreamMatcher
{
   public static int replaceInStream(byte[] find, final byte[] replace, InputStream in, OutputStream out) throws IOException
   {
      final int[] count = new int[1];

      StreamMatcher srm = new StreamMatcher(find)
      {
         @Override
         protected void onMatch(OutputStream out, byte[] match, int off, int len) throws IOException
         {
            out.write(match, off, len);

            count[0]++;
         }

         @Override
         protected void onData(OutputStream out, byte[] data, int off, int len) throws IOException
         {
            out.write(replace);
         }
      };

      try
      {
         srm.transfer(in, out);

         return count[0];
      }
      finally
      {
         Streams.safeClose(in);
         Streams.safeClose(out);
      }
   }

   private final byte[] match;

   public StreamMatcher(byte[] match)
   {
      this.match = match.clone();
   }

   protected abstract void onMatch(OutputStream out, byte[] match, int off, int len) throws IOException;

   protected abstract void onData(OutputStream out, byte[] data, int off, int len) throws IOException;

   public void transfer(InputStream in, OutputStream out) throws IOException
   {
      final byte[] dataBuffer = new byte[match.length];

      int writeOffset = 0;

      while (true)
      {
         {
            // fill data buffer
            int toRead = dataBuffer.length - writeOffset;

            int got = tryReadFully(in, dataBuffer, writeOffset, toRead);

            if (got != toRead)
            {
               this.onData(out, dataBuffer, writeOffset, got);
               break;
            }
         }

         int indexOf = indexOfBeginOfPattern(dataBuffer, match);

         if (indexOf == 0)
         {
            // found delimiter

            this.onMatch(out, dataBuffer, 0, match.length);
            writeOffset = this.consume(out, dataBuffer, writeOffset, match.length, false);
         }
         else if (indexOf == -1)
         {
            // nothing found

            writeOffset = this.consume(out, dataBuffer, writeOffset, dataBuffer.length, true);
         }
         else
         {
            // maybe delimiter

            int before = (indexOf == -1) ? 0 : indexOf;

            writeOffset = this.consume(out, dataBuffer, writeOffset, before, true);
         }
      }
   }

   private final int tryReadFully(InputStream in, byte b[], int off, int len)
   {
      if (len < 0)
         throw new IndexOutOfBoundsException();

      int sum = 0;

      while (sum < len)
      {
         try
         {
            int got = in.read(b, off + sum, len - sum);
            if (got < 0)
               throw new EOFException();
            sum += got;
         }
         catch (IOException exc)
         {
            break;
         }
      }
      return sum;
   }

   private final int consume(OutputStream out, byte[] dataBuffer, int writeOffset, int bytes, boolean isData) throws IOException
   {
      if (bytes == 0)
         return writeOffset;
      if (isData)
         this.onData(out, dataBuffer, 0, bytes);
      if (bytes == dataBuffer.length)
         return 0;

      // compact
      int bytesToKeep = dataBuffer.length - bytes;
      System.arraycopy(dataBuffer, bytes, dataBuffer, 0, bytesToKeep);
      return bytesToKeep;
   }

   // utility methods

   public static int indexOfBeginOfPattern(byte[] data, byte[] pattern)
   {
      if (data.length != pattern.length)
         throw new IllegalStateException();

      for (int i = 0; i < pattern.length; i++)
         if (equalsRange(data, i, pattern, 0, pattern.length - i))
            return i;

      return -1;
   }

   public static int indexOf(byte[] aBuf, byte[] bBuf)
   {
      return indexOf(aBuf, 0, bBuf, 0, bBuf.length, aBuf.length - bBuf.length);
   }

   public static int indexOf(byte[] aBuf, int aOff, byte[] bBuf, int maxIndex)
   {
      return indexOf(aBuf, aOff, bBuf, 0, bBuf.length, maxIndex);
   }

   public static int indexOf(byte[] aBuf, int aOff, byte[] bBuf, int bOff, int bLen, int maxIndex)
   {
      int tries = Math.min((aBuf.length - aOff) - bLen, maxIndex);
      for (int i = 0; i < tries; i++)
         if (equalsRange(aBuf, aOff + i, bBuf, bOff, bLen))
            return i;

      return -1;
   }

   public static boolean equalsRange(byte[] aBuf, int aOff, byte[] bBuf, int bOff, int len)
   {
      for (int i = 0; i < len; i++)
         if (aBuf[aOff + i] != bBuf[bOff + i])
            return false;
      return true;
   }
}
