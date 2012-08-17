/*
 * Created on 16-jun-2005
 */
package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;

import craterstudio.io.Streams;

public class SharingOutputStream extends OutputStream
{
   private final OutputStream[] streams;
   private final boolean[]      closed;
   private int                  closedCount;

   public SharingOutputStream(OutputStream... streams)
   {
      this.streams = streams;
      this.closed = new boolean[streams.length];
      this.closedCount = 0;
   }

   /**
    * WRITE
    */

   public void write(int b) throws IOException
   {
      for (int i = 0; i < streams.length; i++)
      {
         if (closed[i])
            continue;

         try
         {
            streams[i].write(b);
         }
         catch (Exception exc)
         {
            exc.printStackTrace();

            Streams.safeClose(streams[i]);
            closed[i] = true;
            closedCount++;
         }
      }

      if (closedCount == streams.length)
      {
         throw new IOException("All sub-streams are closed");
      }
   }

   public void write(byte[] buf) throws IOException
   {
      this.write(buf, 0, buf.length);
   }

   public void write(byte[] buf, int off, int len) throws IOException
   {
      for (int i = 0; i < streams.length; i++)
      {
         if (closed[i])
            continue;

         try
         {
            streams[i].write(buf, off, len);
         }
         catch (Exception exc)
         {
            exc.printStackTrace();

            Streams.safeClose(streams[i]);
            closed[i] = true;
            closedCount++;
         }
      }

      if (closedCount == streams.length)
      {
         throw new IOException("All sub-streams are closed");
      }
   }

   /**
    * FLUSH
    */

   public void flush() throws IOException
   {
      for (int i = 0; i < streams.length; i++)
      {
         if (closed[i])
            continue;

         try
         {
            streams[i].flush();
         }
         catch (Exception exc)
         {
            exc.printStackTrace();

            Streams.safeClose(streams[i]);
            closed[i] = true;
            closedCount++;
         }
      }

      if (closedCount == streams.length)
      {
         throw new IOException("All sub-streams are closed");
      }
   }

   /**
    * CLOSE
    */

   public void close() throws IOException
   {
      for (int i = 0; i < streams.length; i++)
      {
         if (closed[i])
            continue;

         Streams.safeClose(streams[i]);
         closed[i] = true;
         closedCount++;
      }
   }
}
