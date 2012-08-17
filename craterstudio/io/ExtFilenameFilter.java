/*
 * Created on 9 okt 2008
 */

package craterstudio.io;

import java.io.File;
import java.io.FilenameFilter;

import craterstudio.text.Text;

public class ExtFilenameFilter implements FilenameFilter
{
   private final String[] ext;

   public ExtFilenameFilter(String... ext)
   {
      this.ext = ext;
   }

   @Override
   public boolean accept(File dir, String name)
   {
      String last = Text.afterLast(name, '.');
      for (String ext : this.ext)
         if (ext.equalsIgnoreCase(last))
            return true;
      return false;
   }
}