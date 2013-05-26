/*
 * Created on 2 jul 2009
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

public class AttachableOutputStream extends OutputStream
{
   public AttachableOutputStream()
   {
      this.streams = new HashSet<OutputStream>();
   }

   //

   private Set<OutputStream> streams;

   public void attach(OutputStream out)
   {
      synchronized (this.streams)
      {
         this.streams.add(out);
      }
   }

   public void detach(OutputStream out)
   {
      synchronized (this.streams)
      {
         this.streams.remove(out);
      }
   }

   //

   @Override
   public void write(int b) throws IOException
   {
      synchronized (this.streams)
      {
         Set<OutputStream> remove = null;
         for (OutputStream out : this.streams)
         {
            try
            {
               out.write(b);
            }
            catch (IOException exc)
            {
               if (remove == null)
                  remove = new HashSet<OutputStream>();
               remove.add(out);
            }
         }
         if (remove != null)
            this.streams.remove(remove);
      }
   }

   @Override
   public void write(byte[] buf) throws IOException
   {
      synchronized (this.streams)
      {
         Set<OutputStream> remove = null;
         for (OutputStream out : this.streams)
         {
            try
            {
               out.write(buf);
            }
            catch (IOException exc)
            {
               if (remove == null)
                  remove = new HashSet<OutputStream>();
               remove.add(out);
            }
         }
         if (remove != null)
            this.streams.remove(remove);
      }
   }

   @Override
   public void write(byte[] buf, int off, int len) throws IOException
   {
      synchronized (this.streams)
      {
         Set<OutputStream> remove = null;
         for (OutputStream out : this.streams)
         {
            try
            {
               out.write(buf, off, len);
            }
            catch (IOException exc)
            {
               if (remove == null)
                  remove = new HashSet<OutputStream>();
               remove.add(out);
            }
         }
         if (remove != null)
            this.streams.remove(remove);
      }
   }

   @Override
   public void flush() throws IOException
   {
      synchronized (this.streams)
      {
         Set<OutputStream> remove = null;
         for (OutputStream out : this.streams)
         {
            try
            {
               out.flush();
            }
            catch (IOException exc)
            {
               if (remove == null)
                  remove = new HashSet<OutputStream>();
               remove.add(out);
            }
         }
         if (remove != null)
            this.streams.remove(remove);
      }
   }

   @Override
   public void close() throws IOException
   {
      synchronized (this.streams)
      {
         Set<OutputStream> remove = null;
         for (OutputStream out : this.streams)
         {
            try
            {
               out.close();
            }
            catch (IOException exc)
            {
               if (remove == null)
                  remove = new HashSet<OutputStream>();
               remove.add(out);
            }
         }
         if (remove != null)
            this.streams.remove(remove);
      }
   }
}
