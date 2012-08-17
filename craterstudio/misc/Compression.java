/*
 * Created on 29-jun-2005
 */
package craterstudio.misc;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import craterstudio.io.FileUtil;
import craterstudio.io.Streams;
import craterstudio.text.TextValues;
import craterstudio.time.Interval;
import craterstudio.util.IteratorUtil;

public class Compression
{
   /**
    * GZ
    */

   public static final void gz(File input, File output)
   {
      FileUtil.writeFile(output, Compression.gz(FileUtil.readFile(input)));
   }

   public static final void ungz(File input, File output)
   {
      FileUtil.writeFile(output, Compression.ungz(FileUtil.readFile(input)));
   }

   public static final byte[] gz(byte[] input)
   {
      try
      {
         InputStream in = new ByteArrayInputStream(input);
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         OutputStream out = new GZIPOutputStream(baos);

         Streams.transfer(in, out, true, true);

         return baos.toByteArray();
      }
      catch (IOException exc)
      {
         exc.printStackTrace();

         return null;
      }
   }

   public static final byte[] ungz(byte[] input)
   {
      try
      {
         InputStream in = new GZIPInputStream(new ByteArrayInputStream(input));
         ByteArrayOutputStream out = new ByteArrayOutputStream(input.length * 2);

         Streams.transfer(in, out, true, true);

         return out.toByteArray();
      }
      catch (IOException exc)
      {
         exc.printStackTrace();

         return null;
      }
   }

   /**
    * 
    */

   public static final void zip(File[] inputs, File base, File output, boolean compress)
   {
      try
      {
         ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(output)));

         for (File input : inputs)
         {
            String path = FileUtil.getRelativePath(input, base);

            ZipEntry entry = new ZipEntry(path);
            entry.setTime(input.lastModified());
            entry.setSize(input.length());

            if (input.isDirectory())
               continue;

            zos.putNextEntry(entry);
            zos.setLevel(compress ? ZipEntry.DEFLATED : ZipEntry.STORED);
            Streams.transfer(new FileInputStream(input), zos, true, false);
            zos.closeEntry();
         }

         zos.flush();
         zos.close();
      }
      catch (IOException exc)
      {
         exc.printStackTrace();
      }
   }

   public static class ArchiveEntry
   {
      public final InputStream stream;
      public final long        lastmod;
      public final String      path;

      public ArchiveEntry(File file, String path)
      {
         this(FileUtil.readFile(file), file.lastModified(), path);
      }

      public ArchiveEntry(byte[] data, long lastmod, String path)
      {
         this(new ByteArrayInputStream(data), lastmod, path);
      }

      public ArchiveEntry(InputStream stream, long lastmod, String path)
      {
         this.stream = stream;
         this.lastmod = lastmod;
         this.path = path;
      }

      @Override
      public int hashCode()
      {
         return this.path.hashCode();
      }

      @Override
      public boolean equals(Object obj)
      {
         return this.path.equals(((ArchiveEntry) obj).path);
      }
   }

   public static class FileEntry extends ArchiveEntry
   {
      public FileEntry(File file, String path)
      {
         super(getStream(file), file.lastModified(), path);
      }

      static InputStream getStream(File file)
      {
         if (!file.exists())
         {
            throw new IllegalArgumentException(file.getAbsolutePath());
         }

         if (file.isDirectory())
         {
            return null;
         }

         try
         {
            return new FileInputStream(file);
         }
         catch (IOException exc)
         {
            throw new IllegalStateException(exc);
         }
      }
   }

   public static final void zipDir(File dir, File output, boolean compress)
   {
      List<ArchiveEntry> entries = new ArrayList<ArchiveEntry>();
      for (File file : IteratorUtil.foreach(FileUtil.getFileHierachyIterator(dir)))
      {
         if (file.isDirectory())
            continue;
         String path = FileUtil.getRelativePath(file, dir);
         entries.add(new ArchiveEntry(FileUtil.readFile(file), file.lastModified(), path));
      }

      Compression.zip(entries, output, compress);
   }

   public static final void zip(Iterable<ArchiveEntry> entries, File output, boolean compress)
   {
      try
      {
         FileUtil.ensureFile(output);
         Compression.zip(entries, new FileOutputStream(output), compress);
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public static final void zip(Iterable<ArchiveEntry> entries, OutputStream output, boolean compress)
   {
      try
      {
         ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(output));

         // put meta-inf first and don't compress
         for (ArchiveEntry entry : entries)
            if (entry.stream != null)
               if (entry.path.startsWith("META-INF/"))
                  addEntry(zos, entry, false);

         for (ArchiveEntry entry : entries)
            if (entry.stream != null)
               if (!entry.path.startsWith("META-INF/"))
                  addEntry(zos, entry, compress);

         zos.flush();
         zos.close();
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   private static final void addEntry(ZipOutputStream zos, ArchiveEntry entry, boolean compress) throws IOException
   {
      ZipEntry zipEntry = new ZipEntry(entry.path);
      zipEntry.setTime(entry.lastmod);
      zos.putNextEntry(zipEntry);
      zos.setLevel(compress ? ZipEntry.DEFLATED : ZipEntry.STORED);
      Streams.transfer(entry.stream, zos, true, false);
      zos.closeEntry();
   }

   public static final Iterable<ArchiveEntry> unzip(File input)
   {
      try
      {
         return Compression.unzip(new FileInputStream(input));
      }
      catch (IOException exc)
      {
         throw new IllegalStateException();
      }
   }

   public static final Iterable<ArchiveEntry> unzip(InputStream input)
   {
      List<ArchiveEntry> entries = new ArrayList<ArchiveEntry>();

      try
      {
         ZipInputStream zis = new ZipInputStream(input);

         while (true)
         {
            ZipEntry ze = zis.getNextEntry();
            if (ze == null)
               break;

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Streams.transfer(zis, baos, false, false);
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

            entries.add(new ArchiveEntry(bais, ze.getTime(), ze.getName()));

            zis.closeEntry();
         }

         zis.close();
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }

      return entries;
   }

   public static final List<ZipEntry> zipList(File input)
   {
      List<ZipEntry> entries = new ArrayList<ZipEntry>();

      try
      {
         ZipInputStream zis = new ZipInputStream(new FileInputStream(input));

         while (true)
         {
            ZipEntry ze = zis.getNextEntry();
            if (ze == null)
               break;
            zis.closeEntry();

            entries.add(ze);
         }

         zis.close();
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }

      return entries;
   }

   public static final void unzip(File input, String base, String[] names)
   {
      try
      {
         ZipInputStream zis = new ZipInputStream(new FileInputStream(input));

         while (true)
         {
            ZipEntry ze = zis.getNextEntry();
            if (ze == null)
               break;
            File file = new File(base + ze.getName());
            if (file.isDirectory())
               continue;

            // if entry.name is found in NAMES
            String name = ze.getName();
            boolean found = false;
            for (String name0 : names)
               if (name0.equals(name))
                  found = true;
            if (!found)
               continue;

            FileUtil.ensurePathToFile(file);
            Streams.transfer(zis, new FileOutputStream(file), false, true);
            zis.closeEntry();
            file.setLastModified(ze.getTime());
         }

         zis.close();
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public static final List<String> unzip(File input, String base)
   {
      List<String> names = new ArrayList<String>();

      try
      {
         ZipInputStream zis = new ZipInputStream(new FileInputStream(input));

         while (true)
         {
            ZipEntry ze = zis.getNextEntry();
            if (ze == null)
               break;
            File file = new File(base + ze.getName());
            if (file.isDirectory())
               continue;
            FileUtil.ensurePathToFile(file);

            Streams.transfer(zis, new FileOutputStream(file), false, true);
            zis.closeEntry();
            file.setLastModified(ze.getTime());

            names.add(ze.getName());
         }

         zis.close();
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }

      return names;
   }

   /**
    * RAR
    */

   private static File rar, unrar;

   public static final void setupRAR(File rar, File unrar)
   {
      Compression.rar = rar;
      Compression.unrar = unrar;
   }

   public static final void rar(File input, File output)
   {
      String sExe = "\"" + rar.getAbsolutePath() + "\"";
      String sArg = "a -o+ -ep"; // archive, overwrite, exclude path
      String sSrc = "\"" + input.getAbsolutePath() + "\"";
      String sDst = "\"" + output.getAbsolutePath() + "\"";

      FileUtil.ensurePathToFile(output);

      // construct parameters
      String sExec = sExe + " " + sArg + " " + sDst + " " + sSrc;

      try
      {
         Process p = Runtime.getRuntime().exec(sExec);
         byte[][] streams = Streams.readProcess(p);

         System.out.write(streams[Streams.PROCESS_STDOUT]);
         System.out.flush();

         System.err.write(streams[Streams.PROCESS_STDERR]);
         System.err.flush();
      }
      catch (Exception exc)
      {
         exc.printStackTrace();
      }
   }

   public static final void unrar(File input, File dirOutput)
   {
      String sExe = "\"" + unrar.getAbsolutePath() + "\"";
      String sArg = "e -o+"; // extract, overwrite
      String sArc = "\"" + input.getAbsolutePath() + "\"";
      String sDir = dirOutput.getAbsolutePath();

      // force native file-separator at end
      char sep = System.getProperty("file.separator").charAt(0);
      if (sDir.charAt(sDir.length() - 1) != sep)
         sDir += sep;

      sDir = "\"" + sDir + "\"";

      // construct parameters
      String sExec = sExe + " " + sArg + " " + sArc + " " + sDir;

      System.out.println(sExec);

      try
      {
         Process p = Runtime.getRuntime().exec(sExec);
         byte[][] streams = Streams.readProcess(p);

         System.out.write(streams[Streams.PROCESS_STDOUT]);
         System.out.flush();

         System.err.write(streams[Streams.PROCESS_STDERR]);
         System.err.flush();
      }
      catch (Exception exc)
      {
         exc.printStackTrace();
      }
   }

   /**
    * 7Z SFX
    */

   public static final void extract7zSFX(File input, File dirOutput)
   {
      String sExe = input.getAbsolutePath();
      String sArg = "-y -o"; // assume yes, output dir
      String sDir = dirOutput.getAbsolutePath();

      // construct parameters
      String sExec = sExe + " " + sArg + "" + sDir; // no space!

      try
      {
         Process p = Runtime.getRuntime().exec(sExec);
         byte[][] streams = Streams.readProcess(p);

         System.out.write(streams[Streams.PROCESS_STDOUT]);
         System.out.flush();

         System.err.write(streams[Streams.PROCESS_STDERR]);
         System.err.flush();
      }
      catch (IOException exc)
      {
         exc.printStackTrace();
      }
   }

   /**
    * LIST
    */

   @SuppressWarnings(value = { "unchecked" })
   public static final void createLookupTable(List src, List dst, Map<Integer, Integer> mapping)
   {
      Interval interval = new Interval(1000L);

      for (int i = 0; i < src.size(); i++)
      {
         if (interval.hasPassedAndStep())
         {
            System.out.println((i * 100 / src.size()) + "%");
         }

         Object current = src.get(i);

         // try to find value
         boolean found = false;
         int loc = -1;
         for (int k = 0; k < dst.size(); k++)
         {
            if (dst.get(k).equals(current))
            {
               found = true;
               loc = k;
               break;
            }
         }

         if (found)
         {
            mapping.put(i, loc);
         }
         else
         {
            dst.add(current);

            mapping.put(i, dst.size() - 1);
         }
      }
   }
}