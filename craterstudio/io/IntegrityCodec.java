/*
 * Created on 19-sep-2006
 */

package craterstudio.io;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class IntegrityCodec
{
   public static final void main(String[] args) throws IOException
   {
      File data = new File("K:/Lost.S01E02.HDTV.XviD-LOL.avi");
      File pari = new File("K:/Lost.S01E02.HDTV.XviD-LOL.avi.par");
      //encode(data, pari);
      System.out.println(decode(data, pari));
   }

   public static final void encode(File data, File pari) throws IOException
   {
      byte[] buf = new byte[6];

      InputStream src = new BufferedInputStream(new FileInputStream(data), 64 * 1024);
      DataOutputStream dst = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(pari), 64 * 1024));

      int packetRead = 0;
      int packets = 0;
      while (true)
      {
         int justRead = src.read(buf, packetRead, buf.length - packetRead);
         if (justRead == -1)
            break;
         packetRead += justRead;

         if ((++packets) % 100000 == 0)
            System.out.println(((packets * 6) / 1024 / 1024));

         dst.writeShort(encode6(buf));

         if (packetRead == buf.length)
            packetRead = 0;
      }
      
      src.close();
      dst.close();
   }

   public static final int decode(File data, File pari) throws IOException
   {
      int errors = 0;

      InputStream srcData = new BufferedInputStream(new FileInputStream(data), 64 * 1024);
      InputStream srcPari = new BufferedInputStream(new FileInputStream(pari), 64 * 1024);

      byte[] bufData = new byte[6];
      byte[] bufPari = new byte[2];

      int packets = 0;

      loops: while (true)
      {
         int filledData = 0;
         int filledPari = 0;

         while (filledData != bufData.length)
         {
            int justRead = srcData.read(bufData, filledData, bufData.length - filledData);
            if (justRead == -1)
               break loops;
            filledData += justRead;
         }

         while (filledPari != bufPari.length)
         {
            int justRead = srcPari.read(bufPari, filledPari, bufPari.length - filledPari);
            if (justRead == -1)
               break loops;
            filledPari += justRead;
         }

         if ((++packets) % 100000 == 0)
            System.out.println(((packets * 6) / 1024 / 1024));

         boolean noError = decode6(bufData, (short) ((bufPari[1] & 0xFF) | ((bufPari[0] & 0xFF) << 8)));
         if (!noError)
            errors++;
      }
      
      srcData.close();
      srcPari.close();

      return errors;
   }

   //

   public static final short encode6(byte[] buf)
   {
      if (buf.length < 6)
         throw new IllegalStateException();

      int parityBits = 0;
      int xorBits = 0;

      for (int i = 0; i < 6; i++)
      {
         int srcBits = buf[i] & 0xFF;
         parityBits |= (parity8(srcBits) << i);
         xorBits ^= srcBits;
      }

      return (short) (parityBits | (xorBits << 8));
   }

   //

   /**
    * @return <code>true</code> if all bytes were valid, <code>false</code>
    *         if it was repaired
    * @throws IllegalStateException
    *            if an error could not be repaired
    */

   public static final boolean decode6(byte[] buf, short code)
   {
      if (buf.length < 6)
         throw new IllegalStateException();

      int parityBits = code & 0xFF;
      int xorBits = (code >> 8) & 0xFF;

      int errorAtByte = -1;

      for (int i = 0; i < 6; i++)
      {
         int parityBit = parity8(buf[i] & 0xFF);
         int correctParityBit = (parityBits >> i) & 1;

         if (correctParityBit != parityBit)
         {
            if (errorAtByte != -1)
               throw new IllegalStateException("more than 1 byte-parity corrupt");
            errorAtByte = i;
         }
      }

      if (errorAtByte == -1)
      {
         if (xor6(buf) != xorBits)
            throw new IllegalStateException("hidden error: xor fault");

         return true;
      }

      buf[errorAtByte] = (byte) ((xor6(buf, errorAtByte) ^ xorBits) & 0xFF);

      return false;
   }

   /**
    * UTILITY METHODS
    */

   private static final int xor6(byte[] buf)
   {
      int xor = buf[0] & 0xFF;
      xor ^= buf[1] & 0xFF;
      xor ^= buf[2] & 0xFF;
      xor ^= buf[3] & 0xFF;
      xor ^= buf[4] & 0xFF;
      xor ^= buf[5] & 0xFF;
      return xor;
   }

   private static final int xor6(byte[] buf, int skip)
   {
      int xor = 0;
      if (skip != 0)
         xor ^= buf[0] & 0xFF;
      if (skip != 1)
         xor ^= buf[1] & 0xFF;
      if (skip != 2)
         xor ^= buf[2] & 0xFF;
      if (skip != 3)
         xor ^= buf[3] & 0xFF;
      if (skip != 4)
         xor ^= buf[4] & 0xFF;
      if (skip != 5)
         xor ^= buf[5] & 0xFF;
      return xor;
   }

   private static final int parity8(int bits)
   {
      int parityBit = 0;
      parityBit ^= ((bits >> 7) & 1);
      parityBit ^= ((bits >> 6) & 1);
      parityBit ^= ((bits >> 5) & 1);
      parityBit ^= ((bits >> 4) & 1);
      parityBit ^= ((bits >> 3) & 1);
      parityBit ^= ((bits >> 2) & 1);
      parityBit ^= ((bits >> 1) & 1);
      parityBit ^= ((bits >> 0) & 1);
      return parityBit;
   }
}