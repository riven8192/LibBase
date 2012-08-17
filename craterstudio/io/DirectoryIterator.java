/*
 * Created on 1 dec 2009
 */

package craterstudio.io;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

public class DirectoryIterator
{
   public static void main(String[] args) throws Exception
   {
      DirectoryVisitor visitor = new DirectoryVisitor()
      {
         @Override
         public void visit(File parent, String name)
         {
            System.out.println("file: " + name);
         }
      };

      try
      {
         iterate(new File(args[0]), visitor);
      }
      catch (IllegalStateException exc)
      {
         System.err.println(exc.getMessage());
         System.exit(1);
      }
   }

   public static void iterate(File directory, DirectoryVisitor visitor)
   {
      String path = directory.getAbsolutePath();

      if (!directory.isDirectory())
      {
         throw new IllegalStateException("file not a directory: " + path);
      }

      if (System.getProperty("os.name").toLowerCase().contains("windows"))
      {
         try
         {
            String[] cmd = new String[5];
            cmd[0] = "cmd";
            cmd[1] = "/c";
            cmd[2] = "dir";
            cmd[3] = "/B";
            cmd[4] = path;
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while (true)
            {
               String line = br.readLine();
               if (line == null)
                  break;
               visitor.visit(directory, line);
            }
            int ev = p.waitFor();
            if (ev != 0)
            {
               throw new IllegalStateException("cmd exit value: " + ev);
            }
         }
         catch (Exception exc)
         {
            throw new IllegalStateException(exc);
         }
      }
      else
      {
         try
         {
            String[] cmd = new String[2];
            cmd[0] = "/bin/ls";
            cmd[1] = path;
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while (true)
            {
               String line = br.readLine();
               if (line == null)
                  break;
               visitor.visit(directory, line);
            }
            int ev = p.waitFor();
            if (ev != 0)
            {
               throw new IllegalStateException("/bin/ls exit value: " + ev);
            }
         }
         catch (Exception exc)
         {
            throw new IllegalStateException(exc);
         }
      }
   }
}
