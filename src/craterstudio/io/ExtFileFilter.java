/*
 * Created on 9 okt 2008
 */

package craterstudio.io;

import java.io.File;
import java.io.FileFilter;

import craterstudio.text.Text;

public class ExtFileFilter implements FileFilter
{
   private final String[] ext;

   public ExtFileFilter(String... ext)
   {
      this.ext = ext;
   }

   @Override
   public boolean accept(File pathname)
   {
      String last = Text.afterLast(pathname.getName(), '.');
      for (String ext : this.ext)
         if (ext.equalsIgnoreCase(last))
            return true;
      return false;
   }
}