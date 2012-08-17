/*
 * Created on 4 jun 2010
 */

package craterstudio.streams;

import java.io.InputStream;

import craterstudio.io.Streams;

public class BinaryLineInputStream extends AbstractInputStream
{
   public BinaryLineInputStream(InputStream backing)
   {
      super(backing);
   }

   public String readLine()
   {
      return Streams.binaryReadLineAsString(this.backing);
   }
}
