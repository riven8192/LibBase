/*
 * Created on Apr 5, 2010
 */

package craterstudio.streams;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import craterstudio.text.Text;

public abstract class MultipartBoundaryMatcher
{
   private final byte[] boundary;
   private final byte[] lastpart;

   public MultipartBoundaryMatcher(String multipartBoundary)
   {
      this.boundary = Text.ascii("--" + multipartBoundary + "\r\n");
      this.lastpart = Text.ascii("--" + multipartBoundary + "--");
   }

   public MultipartBoundaryMatcher(byte[] boundary, byte[] lastpart)
   {
      if (boundary.length != lastpart.length)
         throw new IllegalStateException("arrays must have same size");
      this.boundary = boundary.clone();
      this.lastpart = lastpart.clone();
   }

   protected void onBoundary(OutputStream out, byte[] boundary, int off, int len) throws IOException
   {
      out.write(boundary, off, len);
   }

   protected void onData(OutputStream out, byte[] data, int off, int len) throws IOException
   {
      out.write(data, off, len);
   }

   public void transfer(InputStream in, OutputStream out) throws IOException
   {
      final byte[] dataBuffer = new byte[boundary.length];
      DataInputStream readHelper = new DataInputStream(in);

      int writeOffset = 0;

      while (true)
      {
         {
            // fill data buffer
            int toRead = dataBuffer.length - writeOffset;
            readHelper.readFully(dataBuffer, writeOffset, toRead); // throws EOFException
         }

         int indexOf1 = indexOfBeginOfPattern(dataBuffer, boundary);
         int indexOf2 = indexOfBeginOfPattern(dataBuffer, lastpart);

         if (indexOf1 == 0 || indexOf2 == 0)
         {
            // found delimiter

            this.onBoundary(out, dataBuffer, 0, boundary.length);
            writeOffset = this.consume(out, dataBuffer, writeOffset, boundary.length, false);

            if (indexOf2 == 0)
            {
               break;
            }
         }
         else if (indexOf1 == -1 && indexOf2 == -1)
         {
            // nothing found

            writeOffset = this.consume(out, dataBuffer, writeOffset, dataBuffer.length, true);
         }
         else
         {
            // maybe delimiter

            int before1 = (indexOf1 == -1) ? 0 : indexOf1;
            int before2 = (indexOf2 == -1) ? 0 : indexOf2;
            int before = Math.min(before1, before2);

            writeOffset = this.consume(out, dataBuffer, writeOffset, before, true);
         }
      }
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
