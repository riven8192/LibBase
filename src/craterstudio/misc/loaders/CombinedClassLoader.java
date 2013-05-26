package craterstudio.misc.loaders;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class CombinedClassLoader extends ClassLoader
{
   private final ClassLoader[] loaders;

   public CombinedClassLoader(ClassLoader[] loaders)
   {
      this.loaders = loaders;
   }

   @Override
   public URL getResource(String name)
   {
      for (ClassLoader loader : loaders)
      {
         URL url = loader.getResource(name);
         if (url != null)
            return url;
      }

      return null;
   }

   @Override
   public Enumeration<URL> getResources(String name) throws IOException
   {
      List<URL> urls = new ArrayList<URL>();
      for (ClassLoader loader : this.loaders)
         urls.addAll(Collections.list(loader.getResources(name)));
      return Collections.enumeration(urls);
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

   @Override
   public InputStream getResourceAsStream(String name)
   {
      for (ClassLoader loader : this.loaders)
      {
         InputStream in = loader.getResourceAsStream(name);
         if (in != null)
            return in;
      }

      return null;
   }
}