/*
 * Created on 24 dec 2007
 */

package craterstudio.bytes;

import java.util.Random;

public class Arcfour
{
   private final byte[] seq;

   public Arcfour()
   {
      this(256);
   }

   public Arcfour(int bytes)
   {
      this(Arcfour.createRandomKey(bytes));
   }

   public Arcfour(byte[] key)
   {
      this.seq = new byte[256];

      // initiate
      for (int i = 0; i < seq.length; i++)
         seq[i] = (byte) i;

      if (key != null && key.length != 0)
         this.shuffle(key);
   }

   public final void skip(int n)
   {
      for (int i = 0; i < n; i++)
         this.next();
   }

   public final byte crypt(byte value)
   {
      return (byte) (value ^ this.next());
   }

   public final void crypt(byte[] buf, int off, int len)
   {
      int end = off + len;
      for (int i = off; i < end; i++)
         buf[i] = (byte) (buf[i] ^ this.next());
   }

   public Arcfour copy()
   {
      Arcfour copy = new Arcfour(null);
      copy.i = this.i;
      copy.j = this.j;
      for (int i = 0; i < 256; i++)
         copy.seq[i] = this.seq[i];
      return copy;
   }

   private void shuffle(byte[] key)
   {
      int j = 0;
      for (int i = 0; i < 256; i++)
      {
         j = (j + seq[i] + (key[i % key.length] & 0xFF)) & 0xFF;

         seq[i] = (byte) (seq[i] ^ seq[j]);
         seq[j] = (byte) (seq[i] ^ seq[j]);
         seq[i] = (byte) (seq[i] ^ seq[j]);
      }
   }

   private int i, j;

   private final byte next()
   {
      i = (i + 1) & 0xFF;
      j = (j + seq[i]) & 0xFF;

      seq[i] = (byte) (seq[i] ^ seq[j]);
      seq[j] = (byte) (seq[i] ^ seq[j]);
      seq[i] = (byte) (seq[i] ^ seq[j]);

      return seq[(seq[i] + seq[j]) & 0xFF];
   }

   private static final byte[] createRandomKey(int bytes)
   {
      Random r = new Random();

      for (int i = 0; i < 64; i++)
         for (int k = 0; k < r.nextInt(64); k++)
            r.nextInt();

      byte[] key = new byte[bytes];
      r.nextBytes(key);

      return key;
   }
}