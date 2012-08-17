/*
 * Created on 20 jan 2009
 */

package craterstudio.io;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

public class TextFileUtil
{
   public static final void writeFile(File file, String text, String charset)
   {
      try
      {
         FileUtil.writeFile(file, text.getBytes(charset));
      }
      catch (UnsupportedEncodingException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public static final String readFileAsText(File file, String charset)
   {
      byte[] raw = FileUtil.readFile(file);

      if (raw == null)
      {
         return null;
      }

      try
      {
         return new String(raw, charset);
      }
      catch (UnsupportedEncodingException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public static final void writeFileUsingLines(File file, String charset, List<String> lines, String newLine)
   {
      StringBuilder sb = new StringBuilder();
      for (String line : lines)
         sb.append(line).append(newLine);
      TextFileUtil.writeFile(file, sb.toString(), charset);
   }

   public static final Iterable<String> readFileAsLines(File file, String charset)
   {
      try
      {
         final BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file), charset));

         return new Iterable<String>()
         {
            @Override
            public Iterator<String> iterator()
            {
               return new Iterator<String>()
               {
                  String nextLine = null;

                  @Override
                  public boolean hasNext()
                  {
                     if (this.nextLine == null)
                     {
                        try
                        {
                           this.nextLine = br.readLine();
                           if (this.nextLine == null)
                           {
                              Streams.safeClose(br);
                           }
                        }
                        catch (IOException exc)
                        {
                           throw new IllegalStateException(exc);
                        }
                     }
                     return this.nextLine != null;
                  }

                  @Override
                  public String next()
                  {
                     if (!this.hasNext())
                        throw new NoSuchElementException();

                     String line = this.nextLine;
                     this.nextLine = null;
                     return line;
                  }

                  @Override
                  public void remove()
                  {
                     throw new UnsupportedOperationException();
                  }
               };
            }
         };
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }
   }
}
