/*
 * Created on 9 apr 2009
 */

package craterstudio.misc.loaders;

import java.io.InputStream;
import java.net.URL;

public class MultiClassLoader extends ClassLoader
{
   private final ClassLoader[] loaders;

   public MultiClassLoader(ClassLoader parent, ClassLoader... loaders)
   {
      super(parent);

      this.loaders = loaders;
   }

   @Override
   public URL getResource(String name)
   {
      for (ClassLoader loader : this.loaders)
      {
         URL url = loader.getResource(name);
         if (url == null)
            continue;
         return url;
      }

      throw null;
   }

   @Override
   public InputStream getResourceAsStream(String name)
   {
      for (ClassLoader loader : this.loaders)
      {
         InputStream in = loader.getResourceAsStream(name);
         if (in == null)
            continue;
         return in;
      }

      throw null;
   }

   @Override
   public Class< ? > loadClass(String name) throws ClassNotFoundException
   {
      for (ClassLoader loader : this.loaders)
      {
         try
         {
            return loader.loadClass(name);
         }
         catch (ClassNotFoundException exc)
         {
            continue;
         }
      }

      throw new ClassNotFoundException(name);
   }
}
