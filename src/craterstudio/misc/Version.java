/*
 * Created on 4 apr 2011
 */

package craterstudio.misc;

import java.net.URL;
import java.util.Date;

public class Version
{
   @SuppressWarnings("deprecation")
   public static String date(Class< ? > type)
   {
      return new Date(timestamp(type)).toGMTString();
   }

   public static long timestamp(Class< ? > type)
   {
      try
      {
         URL url = find(type);
         if (url == null)
            return 0L;

         return url.openConnection().getLastModified();
      }
      catch (Exception exc)
      {
         exc.printStackTrace();
         return 0L;
      }
   }

   public static URL find(Class< ? > type)
   {
      return Version.class.getClassLoader().getResource(type.getName().replace('.', '/') + ".class");
   }
}
