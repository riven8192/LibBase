/*
 * Created on Mar 7, 2010
 */

package craterstudio.io;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.RandomAccess;

import craterstudio.text.Text;

public class FileSorter
{
   public static void sort(File[] files, int queryMask, Comparator<FileMetaData>... comps)
   {
      FileMetaData[] metas = convert(files, queryMask);
      Arrays.sort(metas, FileSorter.sortBy(comps));
      for (int i = 0; i < files.length; i++)
         files[i] = metas[i].file;
   }

   public static void sort(List<File> files, int queryMask, Comparator<FileMetaData>... comps)
   {
      List<FileMetaData> metas = convert(files, queryMask);
      Collections.sort(metas, FileSorter.sortBy(comps));

      if (files instanceof RandomAccess)
      {
         int p = 0;
         for (FileMetaData meta : metas)
            files.set(p++, meta.file);
      }
      else
      {
         files.clear();
         for (FileMetaData meta : metas)
            files.add(meta.file);
      }
   }

   //

   private static FileMetaData[] convert(File[] files, int queryMask)
   {
      FileMetaData[] fmd = new FileMetaData[files.length];
      for (int i = 0; i < files.length; i++)
         fmd[i] = new FileMetaData(files[i], queryMask);
      return fmd;
   }

   private static List<FileMetaData> convert(Iterable<File> files, int queryMask)
   {
      List<FileMetaData> list = new ArrayList<FileMetaData>();
      for (File file : files)
         list.add(new FileMetaData(file, queryMask));
      return list;
   }

   //

   public static final Comparator<FileMetaData> sortByName(boolean ascending, boolean ignoreCase)
   {
      Comparator<FileMetaData> comp;
      if (ignoreCase)
         comp = new Comparator<FileMetaData>()
         {
            @Override
            public int compare(FileMetaData a, FileMetaData b)
            {
               return a.name.compareToIgnoreCase(b.name);
            }
         };
      else
         comp = new Comparator<FileMetaData>()
         {
            @Override
            public int compare(FileMetaData a, FileMetaData b)
            {
               return a.name.compareTo(b.name);
            }
         };
      if (!ascending)
         comp = Collections.reverseOrder(comp);
      return comp;
   }

   public static final Comparator<FileMetaData> sortByExtension(boolean ascending)
   {
      Comparator<FileMetaData> comp = new Comparator<FileMetaData>()
      {
         @Override
         public int compare(FileMetaData a, FileMetaData b)
         {
            String aName = a.name;
            String bName = b.name;
            String aExt = Text.afterLast(aName, '.');
            String bExt = Text.afterLast(bName, '.');
            if (aExt == null ^ bExt == null)
               return aExt != null ? -1 : +1;
            if (aExt == null /*be too*/)
               return 0;
            return aExt.compareToIgnoreCase(bExt);
         }
      };
      if (!ascending)
         comp = Collections.reverseOrder(comp);
      return comp;
   }

   public static final Comparator<FileMetaData> sortByLength(boolean ascending)
   {
      Comparator<FileMetaData> comp = new Comparator<FileMetaData>()
      {
         @Override
         public int compare(FileMetaData a, FileMetaData b)
         {
            return Long.signum(b.length - a.length);
         }
      };
      if (!ascending)
         comp = Collections.reverseOrder(comp);
      return comp;
   }

   public static final Comparator<FileMetaData> sortByLastMod(boolean ascending)
   {
      Comparator<FileMetaData> comp = new Comparator<FileMetaData>()
      {
         @Override
         public int compare(FileMetaData a, FileMetaData b)
         {
            return Long.signum(a.lastmod - b.lastmod);
         }
      };
      if (!ascending)
         comp = Collections.reverseOrder(comp);
      return comp;
   }

   public static final Comparator<FileMetaData> sortByIsDirectory(boolean ascending)
   {
      Comparator<FileMetaData> comp = new Comparator<FileMetaData>()
      {
         @Override
         public int compare(FileMetaData a, FileMetaData b)
         {
            return Integer.signum((a.isDirectory ? 0 : 1) - (b.isDirectory ? 0 : 1));
         }
      };
      if (!ascending)
         comp = Collections.reverseOrder(comp);
      return comp;
   }

   public static final Comparator<FileMetaData> sortBy(final Comparator<FileMetaData>... comps)
   {
      return new Comparator<FileMetaData>()
      {
         @Override
         public int compare(FileMetaData a, FileMetaData b)
         {
            int i;
            for (Comparator<FileMetaData> comp : comps)
               if ((i = comp.compare(a, b)) != 0)
                  return i;
            return 0;
         }
      };
   }
}
