/*
 * Created on 24 dec 2007
 */

package craterstudio.data;

import craterstudio.bytes.Arcfour;

public class EncryptedByteArray
{
   private final Arcfour encoder;
   private Arcfour       decoder;
   private byte[]        data;

   public EncryptedByteArray()
   {
      this(0);
   }

   public EncryptedByteArray(int bytes)
   {
      this.encoder = new Arcfour();
      this.data = new byte[bytes];
   }

   //

   public final void set(int index, byte value)
   {
      this.decoder = this.encoder.copy();
      this.encoder.skip(index - 1);
      data[index] = this.encoder.crypt(value);
   }

   public final byte get(int index)
   {
      this.decoder = this.decoder.copy();
      this.encoder.skip(index - 1);
      return this.decoder.crypt(data[index]);
   }

   public final void renew()
   {
      this.decoder = this.encoder.copy();
      this.encoder.crypt(data, 0, data.length);
   }
}