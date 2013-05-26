package craterstudio.misc.loaders;

import java.io.*;
import java.net.URL;
import java.util.*;

public abstract class DynamicClassLoader extends ClassLoader
{
   private ClassLoader currentLoader;

   public DynamicClassLoader()
   {
      super();
      this.currentLoader = null;
   }

   public DynamicClassLoader(ClassLoader parent)
   {
      super(parent);
      this.currentLoader = null;
   }

   //

   public abstract boolean isUpdated();

   public abstract ClassLoader createClassLoader();

   //

   @Override
   public URL getResource(String name)
   {
      this.ensureLatestClassLoader();

      URL url = this.getParent().getResource(name);
      if (url != null)
         return url;

      return this.currentLoader.getResource(name);
   }

   @Override
   public Enumeration<URL> getResources(String name) throws IOException
   {
      this.ensureLatestClassLoader();

      Enumeration<URL> urls = this.getParent().getResources(name);
      if (urls != null)
         return urls;

      return this.currentLoader.getResources(name);
   }

   @Override
   public InputStream getResourceAsStream(String name)
   {
      this.ensureLatestClassLoader();

      InputStream in = this.getParent().getResourceAsStream(name);
      if (in != null)
         return in;

      return this.currentLoader.getResourceAsStream(name);
   }

   public synchronized Class< ? > loadClass(String name) throws ClassNotFoundException
   {
      this.ensureLatestClassLoader();

      return this.currentLoader.loadClass(name);
   }

   //

   private long lastChecked;
   private long minCheckInterval = 0;

   public void setMinimalCheckInterval(long interval)
   {
      this.minCheckInterval = interval;
   }

   private final boolean checkForUpdate()
   {
      long now = System.currentTimeMillis();
      long elapsed = now - this.lastChecked;

      if (elapsed < this.minCheckInterval)
      {
         // if we checked less than N ms ago,
         // just assume the loader is not updated.
         // otherwise we put a major strain on
         // the file system (?) for no real gain
         return false;
      }

      this.lastChecked = now;

      return this.isUpdated();
   }

   //

   public void ensureLatestClassLoader()
   {
      if (this.checkForUpdate())
      {
         this.replaceClassLoader();
      }
   }

   protected void replaceClassLoader()
   {
      this.currentLoader = this.createClassLoader();

      // protected, so do stuff, if you wish
   }
}