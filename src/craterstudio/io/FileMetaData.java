/*
 * Created on Mar 7, 2010
 */

package craterstudio.io;

import java.io.File;

public class FileMetaData
{
   public static final int NAME         = 1 << 0;
   public static final int LENGTH       = 1 << 1;
   public static final int LASTMOD      = 1 << 2;
   public static final int IS_DIRECTORY = 1 << 4;

   //

   public final File       file;
   public final int        queryMask;
   public final String     name;
   public final long       length;
   public final long       lastmod;
   public final boolean    isDirectory;

   public FileMetaData(File file, int queryMask)
   {
      this.file = file;
      this.queryMask = queryMask;

      if ((this.queryMask & NAME) != 0)
         this.name = file.getName();
      else
         this.name = null;

      if ((this.queryMask & LENGTH) != 0)
         this.length = file.length();
      else
         this.length = -1L;

      if ((this.queryMask & LASTMOD) != 0)
         this.lastmod = file.lastModified();
      else
         this.lastmod = -1L;

      if ((this.queryMask & IS_DIRECTORY) != 0)
         this.isDirectory = file.isDirectory();
      else
         this.isDirectory = false;
   }
}