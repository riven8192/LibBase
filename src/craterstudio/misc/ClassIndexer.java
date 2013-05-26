/*
 * Created on 3 aug 2010
 */

package craterstudio.misc;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import craterstudio.io.FileUtil;
import craterstudio.text.Text;
import craterstudio.util.HighLevel;
import craterstudio.util.IteratorUtil;

public class ClassIndexer
{
   private static Map<String, Set<String>>             package_to_classnames;
   private static Map<String, Map<String, Class< ? >>> package_to_classes;

   static
   {
      package_to_classnames = new HashMap<String, Set<String>>();
      package_to_classes = new HashMap<String, Map<String, Class< ? >>>();

      init();
   }

   public static Set<String> getPackagenames()
   {
      return new HashSet<String>(package_to_classnames.keySet());
   }

   public static Set<String> getPackageClassnames(String packagename)
   {
      Set<String> classnames = package_to_classnames.get(packagename);
      if (classnames == null)
         throw new NoSuchElementException("package not found: '" + packagename + "'");

      return new HashSet<String>(classnames);
   }

   public static Map<String, Class< ? >> getPackageClasses(String packagename)
   {
      Map<String, Class< ? >> classes = package_to_classes.get(packagename);

      if (classes == null)
      {
         package_to_classes.put(packagename, classes = new HashMap<String, Class< ? >>());

         for (String classname : getPackageClassnames(packagename))
         {
            try
            {
               Class< ? > clazz = Class.forName(packagename + "." + classname);
               classes.put(classname, clazz);
            }
            catch (Exception exc)
            {
               exc.printStackTrace(); // ignore             
            }
         }
      }

      return new HashMap<String, Class< ? >>(classes);
   }

   private static void init()
   {
      for (URL url : HighLevel.getBootClassPath())
      {
         try
         {
            indexURL(url);
         }
         catch (IOException exc)
         {
            exc.printStackTrace();
         }
      }

      for (URL url : HighLevel.getClassPath())
      {
         try
         {
            indexURL(url);
         }
         catch (IOException exc)
         {
            exc.printStackTrace();
         }
      }
   }

   public static void indexURL(URL url) throws IOException
   {
      if (url.getProtocol().equals("file"))
      {
         File file = new File(url.getPath());
         if (!file.exists())
            return;

         if (file.isDirectory())
         {
            for (File f : FileUtil.getFileHierachyIterable(file))
            {
               if (f.isDirectory())
                  continue;
               handleEntry(FileUtil.getRelativePath(f, file));
            }
         }
         else
         {
            ZipFile zf = new ZipFile(file);
            for (ZipEntry ze : IteratorUtil.foreach(zf.entries()))
               handleEntry(ze.getName());
            zf.close();
         }
      }
      else
      {
         throw new IllegalStateException(url.toString());
      }
   }

   private static void handleEntry(String name)
   {
      if (!name.endsWith(".class"))
         return;

      name = Text.beforeLast(name, ".class");
      name = Text.replace(name, '/', '.');

      if (name.indexOf('.') == -1)
         return;

      String packagename = Text.beforeLast(name, '.');
      String classname = Text.afterLast(name, '.');

      if (classname.contains("$"))
         return;

      Set<String> classnames = package_to_classnames.get(packagename);
      if (classnames == null)
         package_to_classnames.put(packagename, classnames = new HashSet<String>());
      classnames.add(classname);
   }
}
