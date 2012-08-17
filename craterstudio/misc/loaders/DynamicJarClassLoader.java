package craterstudio.misc.loaders;

import java.io.*;
import java.util.*;
import java.util.jar.*;

import craterstudio.io.Logger;

public class DynamicJarClassLoader extends DynamicClassLoader
{
   private final File        jar;
   private long              prevLastModified;
   private final Set<String> resourceNames;

   public DynamicJarClassLoader(ClassLoader parent, File jar)
   {
      super(parent);

      this.jar = jar;
      this.prevLastModified = -1L;
      this.resourceNames = new HashSet<String>();

      this.ensureLatestClassLoader();
   }

   public File getJar()
   {
      return this.jar;
   }

   public Set<String> getResourceNames()
   {
      return Collections.unmodifiableSet(this.resourceNames);
   }

   private static final long file_idle_timeout = 3 * 1000;

   @Override
   public boolean isUpdated()
   {
      long jarLastModified = this.jar.lastModified();

      boolean willBeUpdated = jarLastModified != this.prevLastModified;

      if (willBeUpdated && this.prevLastModified != -1L)
      {
         if (this.jar.lastModified() > System.currentTimeMillis() - file_idle_timeout)
         {
            Logger.notification("Pending new JAR file: %s", this.jar.getAbsolutePath());
            willBeUpdated = false;
         }
      }

      if (willBeUpdated)
      {
         Logger.notification("Loading new JAR file: %s", this.jar.getAbsolutePath());
         this.prevLastModified = jarLastModified;
      }

      return willBeUpdated;
   }

   @Override
   public ClassLoader createClassLoader()
   {
      final Map<String, byte[]> resources;

      this.resourceNames.clear();

      try
      {
         resources = this.loadCompleteJarFile();
      }
      catch (IOException exc)
      {
         throw new IllegalStateException("Failed to load JAR file: " + this.jar.getAbsolutePath(), exc);
      }

      this.resourceNames.addAll(resources.keySet());

      ClassLoader loader = new BytesClassLoader(this.getParent())
      {
         @Override
         public byte[] readBytes(String classname, String name)
         {
            return resources.get(name);
         }
      };

      return loader;
   }

   private final Map<String, byte[]> loadCompleteJarFile() throws IOException
   {
      Map<String, byte[]> map = new HashMap<String, byte[]>();

      JarFile jf = new JarFile(this.jar);
      Enumeration<JarEntry> entries = jf.entries();
      while (entries.hasMoreElements())
      {
         byte[] buf = null;

         JarEntry entry = entries.nextElement();

         if (!entry.isDirectory())
         {
            buf = new byte[(int) entry.getSize()];
            InputStream in = jf.getInputStream(entry);
            int off = 0;
            while (off != buf.length)
            {
               int justRead = in.read(buf, off, buf.length - off);
               if (justRead == -1)
                  throw new EOFException("Could not fully read JAR file entry: " + entry.getName());
               off += justRead;
            }
            in.close();
         }

         map.put(entry.getName(), buf);
      }

      jf.close();

      return map;
   }
}