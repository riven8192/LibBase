/*
 * Created on 5 jan 2010
 */

package craterstudio.encryption;

import java.util.Arrays;

public class KeytoolKey
{
   final KeytoolStore store;
   final String       alias;
   final byte[]       password;

   public KeytoolKey(KeytoolStore store, String alias, byte[] password)
   {
      this.store = store;
      this.alias = alias;
      this.password = password;
   }
   
   public KeytoolStore getStore()
   {
      return this.store;
   }

   public void discard()
   {
      Arrays.fill(this.password, (byte) 0);
   }
}
