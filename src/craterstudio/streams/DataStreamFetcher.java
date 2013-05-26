/*
 * Created on 30 sep 2008
 */

package craterstudio.streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class DataStreamFetcher
{
   public static final DataInputStream reverse(byte[] data)
   {
      return new DataInputStream(new ByteArrayInputStream(data));
   }

   ByteArrayOutputStream              baos;
   private final DataOutputStream dos;

   public DataStreamFetcher()
   {
      this.baos = new ByteArrayOutputStream();
      this.dos = new DataOutputStream(this.baos);
   }

   public DataOutputStream getDataOutputStream()
   {
      return this.dos;
   }

   public byte[] toByteArray()
   {
      try
      {
         dos.flush();
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }

      return baos.toByteArray();
   }
}