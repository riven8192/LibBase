/*
 * Created on 27-mei-2006
 */

package craterstudio.bytes;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;

public class XOR
{
   public static final byte[] generateKey(int length, byte[] input)
   {
      byte[] key = new byte[length];

      for (int k = 0; k < input.length; k++)
      {
         byte[] seed = input.clone();
         scramble(seed, new SecureRandom(input));
         input = seed;

         for (int i = 0; i < key.length; i++)
            key[i] ^= seed[i];
      }

      return key;
   }

   private static final void scramble(byte[] data, Random r)
   {
      for (int to = 0; to < data.length; to++)
      {
         int from = r.nextInt(data.length - to);
         byte temp = data[to];
         data[to] = data[from];
         data[from] = temp;
      }
   }

   /**
    * byte[]
    */

   public static final byte[] xor(byte[] data, byte[] key)
   {
      for (int i = 0; i < data.length; i++)
      {
         int a = data[i] & 0xFF;
         int b = key[i % key.length] & 0xFF;
         data[i] = (byte) (a ^ b);
      }

      return data;
   }

   public static final byte[] xor(byte[] data, int off, int len, byte[] key, int pos)
   {
      for (int i = 0; i < len; i++)
      {
         int a = data[off + i] & 0xFF;
         int b = key[(pos + i) % key.length] & 0xFF;
         data[off + i] = (byte) (a ^ b);
      }

      return data;
   }

   /**
    * ByteBuffer
    */

   public static final ByteBuffer xor(ByteBuffer data, ByteBuffer key)
   {
      int p0 = data.position();
      int r0 = data.remaining();
      int r1 = key.remaining();

      for (int i = 0; i < r0; i++)
      {
         int p = p0 + i;
         int a = data.get(p) & 0xFF;
         int b = key.get(i % r1) & 0xFF;
         data.put(p, (byte) (a ^ b));
      }

      return data;
   }

   public static final ByteBuffer xor(ByteBuffer data, int off, int len, ByteBuffer key, int pos)
   {
      int p0 = data.position();
      int r1 = key.remaining();

      for (int i = 0; i < len; i++)
      {
         int p = p0 + i;
         int a = data.get(off + p) & 0xFF;
         int b = key.get((pos + i) % r1);
         data.put(off + p, (byte) (a ^ b));
      }

      return data;
   }
}
