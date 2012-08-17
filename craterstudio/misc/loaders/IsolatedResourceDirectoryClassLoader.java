package craterstudio.misc.loaders;

import java.io.*;

import craterstudio.io.FileUtil;

public class IsolatedResourceDirectoryClassLoader extends DynamicClassLoader
{
   final File dir;

   public IsolatedResourceDirectoryClassLoader(File dir)
   {
      super();

      this.dir = dir;
   }

   public IsolatedResourceDirectoryClassLoader(ClassLoader parent, File dir)
   {
      super(parent);

      this.dir = dir;
   }

   @Override
   public boolean isUpdated()
   {
      return true;
   }

   @Override
   public ClassLoader createClassLoader()
   {
      return new BytesClassLoader(this.getParent())
      {
         @Override
         public byte[] readBytes(String classname, String path)
         {
            try
            {
               return FileUtil.readFile(new File(dir, path));
            }
            catch (IllegalArgumentException exc)
            {
               throw new NoClassDefFoundError(classname);
            }
         }
      };
   }
}