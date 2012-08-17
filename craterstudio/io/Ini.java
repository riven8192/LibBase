package craterstudio.io;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;

public class Ini extends HashMap<String, Ini.Section>
{
   private static final long serialVersionUID = -901382561263589235L;

   /**
    * SECTION
    */

   public final void putSection(Section section)
   {
      this.put(section.getName(), section);
   }

   public final Section getSection(String name)
   {
      return this.get(name);
   }

   public final Section createSection(String name)
   {
      Section section = new Section(name);
      this.putSection(section);
      return section;
   }

   /**
    * LOAD
    */

   public final void load(File file) throws IOException
   {
      this.load(new BufferedReader(new FileReader(file)));
   }

   public final void load(BufferedReader reader) throws IOException
   {
      String line = null;

      Section current = null;

      while ((line = reader.readLine()) != null)
      {
         line = line.trim();

         if (line.contains(";"))
            line = line.substring(0, line.indexOf(";")).trim();

         if (line.equals(""))
            continue;

         if (line.startsWith("[") && line.endsWith("]"))
         {
            String name = line.substring(1, line.length() - 1);
            this.put(name, current = new Section(name));

            continue;
         }

         if (line.contains("="))
         {
            int index = line.indexOf("=");
            String key = line.substring(0, index).trim();
            String val = line.substring(index + 1).trim();
            current.put(key, val);

            continue;
         }

         throw new IllegalStateException("could not parse line: " + line);
      }

      reader.close();
   }

   /**
    * STORE
    */

   public final void store(File file) throws IOException
   {
      PrintWriter writer = new PrintWriter(file);
      this.store(writer);
      writer.close();
   }

   private static final boolean SORT_ON_STORE = true;

   public final void store(PrintWriter writer)
   {
      if (SORT_ON_STORE)
      {
         String[] sectionNames = this.keySet().toArray(new String[0]);
         Arrays.sort(sectionNames, String.CASE_INSENSITIVE_ORDER);

         for (String sectionName : sectionNames)
            this.get(sectionName).store(writer);
      }
      else
      {
         for (Section section : this.values())
            section.store(writer);
      }
   }

   /**
    * PRINT
    */

   public final void print()
   {
      for (Ini.Section section : this.values())
      {
         System.out.println("[" + section.getName() + "]");
         for (String key : section.keySet())
            System.out.println(key + "=" + section.get(key));
         System.out.println();
      }
   }

   /**
    * ENTRY
    */

   public class Section extends HashMap<String, String>
   {
      private static final long serialVersionUID = -374650983649128635L;

      public Section(String name)
      {
         this.name = name;
      }

      public Ini getIni()
      {
         return Ini.this;
      }

      /**
       * NAME
       */

      private final String name;

      public final String getName()
      {
         return name;
      }

      /**
       * GET DEFAULT
       */

      public final String get(String key, String def)
      {
         String val = this.get(key);
         if (val == null)
            val = def;
         return val;
      }

      //

      public final boolean getBoolean(String key)
      {
         return Boolean.parseBoolean(this.get(key));
      }

      public final int getInt(String key)
      {
         return Integer.parseInt(this.get(key));
      }

      public final long getLong(String key)
      {
         return Long.parseLong(this.get(key));
      }

      //

      public final boolean getBoolean(String key, boolean def)
      {
         String val = this.get(key);

         if (val == null)
            return def;

         try
         {
            return Boolean.parseBoolean(val);
         }
         catch (Exception exc)
         {
            return def;
         }
      }

      public final int getInt(String key, int def)
      {
         String val = this.get(key);

         if (val == null)
            return def;

         try
         {
            return Integer.parseInt(val);
         }
         catch (Exception exc)
         {
            return def;
         }
      }

      public final long getLong(String key, long def)
      {
         String val = this.get(key);

         if (val == null)
            return def;

         try
         {
            return Long.parseLong(val);
         }
         catch (Exception exc)
         {
            return def;
         }
      }

      /**
       * STORE
       */

      public final void store(PrintWriter writer)
      {
         writer.println("[" + this.getName() + "]");
         if (SORT_ON_STORE)
         {
            String[] keys = this.keySet().toArray(new String[0]);
            Arrays.sort(keys, String.CASE_INSENSITIVE_ORDER);

            for (String key : keys)
               writer.println(key + "=" + this.get(key));
         }
         else
         {
            for (String key : this.keySet())
               writer.println(key + "=" + this.get(key));
         }
         writer.println();
      }
   }
}