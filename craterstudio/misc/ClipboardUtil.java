/*
 * Created on 26-jun-2007
 */

package craterstudio.misc;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;

import craterstudio.util.FunctionPointer;
import craterstudio.util.HighLevel;

public class ClipboardUtil
{
   private static String defaultCharset = "ISO-8859-1";

   public static final void setDefaultCharset(String charset)
   {
      defaultCharset = charset;
   }

   public static void setClipboardText(String text)
   {
      setClipboardText(text, defaultCharset);
   }

   public static void setClipboardText(String text, String charset)
   {
      try
      {
         final Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
         final String mimetype = "text/plain;class=java.io.InputStream;charset=" + charset;
         final DataFlavor flavor = new DataFlavor(mimetype);

         final byte[] raw;
         {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Writer writer = new OutputStreamWriter(baos, charset);
            writer.write(text);
            writer.flush();
            writer.close();
            raw = baos.toByteArray();
         }

         //

         clipboard.setContents(new Transferable()
         {
            public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException, IOException
            {
               for (DataFlavor df : this.getTransferDataFlavors())
                  if (df.match(flavor))
                     return new ByteArrayInputStream(raw);
               throw new UnsupportedFlavorException(flavor);
            }

            public DataFlavor[] getTransferDataFlavors()
            {
               return new DataFlavor[] { flavor };
            }

            public boolean isDataFlavorSupported(DataFlavor flavor)
            {
               for (DataFlavor df : this.getTransferDataFlavors())
                  if (df.match(flavor))
                     return true;
               return false;
            }
         }, null);
      }
      catch (Exception exc)
      {
         throw new IllegalStateException("failed to set clipboard", exc);
      }
   }

   //

   public static String getClipboardText()
   {
      return getClipboardText(defaultCharset);
   }

   public static String getClipboardText(String charset)
   {
      try
      {
         final Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
         final String mimetype = "text/plain;class=java.io.InputStream;charset=" + charset;
         final DataFlavor flavor = new DataFlavor(mimetype);

         Object data = clipboard.getData(flavor);
         if (!(data instanceof InputStream))
            throw new IllegalStateException("unexpected format: " + ((data == null) ? null : data.getClass().getName()));

         char[] buf = new char[1024];
         int count;
         StringBuilder contents = new StringBuilder();

         InputStream input = (InputStream) data;
         Reader reader = new InputStreamReader(input, charset);
         while ((count = reader.read(buf)) != -1)
            contents.append(buf, 0, count);
         reader.close();

         return contents.toString();
      }
      catch (ClassNotFoundException exc)
      {
         // never happens (java.io.InputStream will always be found)
         throw new IllegalStateException("will never happen", exc);
      }
      catch (UnsupportedFlavorException exc)
      {
         return null;
      }
      catch (IllegalStateException exc) // clipboard currently unavailable
      {
         return null;
      }
      catch (IOException exc)
      {
         return null;
      }
   }

   //

   public static void launchClipboardMonitor(final FunctionPointer callback, final int interval)
   {
      new Thread()
      {
         @Override
         public void run()
         {
            String last = null;

            while (true)
            {
               String curr = ClipboardUtil.getClipboardText();

               if (curr == null)
               {
                  // cleared
                  if (last != null)
                     callback.pass(curr).call();
               }
               else if (last == null) // && curr != null)
               {
                  // filled
                  callback.pass(curr).call();
               }
               else if (!last.equals(curr))
               {
                  // changed
                  callback.pass(curr).call();
               }
               else
               {
                  // same
               }

               last = curr;

               HighLevel.sleep(interval);
            }
         }
      }.start();
   }
}