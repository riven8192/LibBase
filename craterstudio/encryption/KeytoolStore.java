/*
 * Created on 5 jan 2010
 */

package craterstudio.encryption;

import java.io.File;
import java.util.Arrays;

public class KeytoolStore
{
   final File   file;
   final byte[] password;

   public KeytoolStore(File keystore, byte[] password)
   {
      this.file = keystore;
      this.password = password;
   }

   public void discard()
   {
      Arrays.fill(this.password, (byte) 0);
   }
}
