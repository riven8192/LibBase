/*
 * Created on 9 apr 2009
 */

package craterstudio.misc.loaders;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;

import craterstudio.io.FileUtil;

public class DynamicFile
{
   private final File file;
   private long       lastMod;
   private byte[]     cached;

   public DynamicFile(File file) throws FileNotFoundException
   {
      if (!file.exists())
      {
         throw new FileNotFoundException(file.getAbsolutePath());
      }

      this.file = file;
      this.lastMod = -1L;
      this.cached = null;
   }

   public File getFile()
   {
      return this.file;
   }

   public boolean exists()
   {
      return this.file.exists();
   }

   public boolean isOutOfDate()
   {
      long curr = this.file.lastModified();
      long prev = this.lastMod;

      return curr != prev;
   }

   public long timeSinceLastMod()
   {
      return System.currentTimeMillis() - this.file.lastModified();
   }

   public void sync()
   {
      this.lastMod = this.file.lastModified();
   }

   public InputStream newInputStream() throws FileNotFoundException
   {
      if (this.cached == null || this.isOutOfDate())
      {
         if (!file.exists())
         {
            throw new FileNotFoundException(file.getAbsolutePath());
         }

         this.cached = FileUtil.readFile(this.file);
         this.lastMod = this.file.lastModified();
      }

      return new ByteArrayInputStream(this.cached);
   }
}
