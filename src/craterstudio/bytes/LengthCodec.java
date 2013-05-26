/*
 * Created on 11 dec 2007
 */

package craterstudio.bytes;

public class LengthCodec
{
   /**
    * ENCODE / DECODE
    */

   public static final int encodeLength(int len, byte[] max4)
   {
      if (len == -1 || len >= 0x40000000)
         throw new IllegalStateException();

      if (len < 0x40) // 64B
      {
         max4[0] = (byte) (len & 0x3F); // 00...
         return 1;
      }

      if (len < 0x4000) // 16KB
      {
         max4[0] = (byte) (((len >> 8) & 0x3F) | 0x40); // 01...
         max4[1] = (byte) ((len >> 0) & 0xFF);
         return 2;
      }

      if (len < 0x400000) // 4MB
      {
         max4[0] = (byte) (((len >> 16) & 0x3F) | 0x80); // 10...
         max4[1] = (byte) ((len >> 8) & 0xFF);
         max4[2] = (byte) ((len >> 0) & 0xFF);
         return 3;
      }

      // 1GB
      max4[0] = (byte) (((len >> 24) & 0x3F) | 0xC0); // 11...
      max4[1] = (byte) ((len >> 16) & 0xFF);
      max4[2] = (byte) ((len >> 8) & 0xFF);
      max4[3] = (byte) ((len >> 0) & 0xFF);
      return 4;
   }

   public static final int decodeLength(byte[] max4)
   {
      int len = max4[0] & 0x3F;// unset 2 highest bits
      int bits = decodeLengthBits(max4[0]);

      for (int i = 1; i < bits; i++)
         len = (len << 8) | (max4[i] & 0xFF);

      return len;
   }

   public static final int decodeLengthBits(byte b)
   {
      return (b & 0xFF) >> 6;
   }
}
