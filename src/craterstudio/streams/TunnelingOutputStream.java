/*
 * Created on 1 jun 2010
 */

package craterstudio.streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;

import craterstudio.io.PrimIO;
import craterstudio.io.Streams;

public class TunnelingOutputStream
{
   public static final int    OPEN  = -1337;
   public static final int    CLOSE = -13370000;

   private final OutputStream backing;

   public TunnelingOutputStream(OutputStream out)
   {
      this.backing = out;
   }

   public void close()
   {
      Streams.safeClose(this.backing);
   }

   public OutputStream createOutputStream(final int id) throws IOException
   {
      final OutputStream dst = this.backing;
      final byte[] header = new byte[8];
      PrimIO.writeInt(header, id);

      return new OutputStream()
      {
         private boolean open = false;

         {
            synchronized (dst)
            {
               PrimIO.writeInt(header, 4, OPEN);
               dst.write(header);
               dst.flush();
               this.open = true;
            }
         }

         @Override
         public void write(int b) throws IOException
         {
            this.write(new byte[] { (byte) b });
         }

         @Override
         public void write(byte[] buf) throws IOException
         {
            this.write(buf, 0, buf.length);
         }

         @Override
         public void write(byte[] buf, int off, int len) throws IOException
         {
            if (len < 0)
            {
               throw new IllegalArgumentException();
            }

            synchronized (dst)
            {
               if (!this.open)
                  throw new EOFException("stream closed");
               PrimIO.writeInt(header, 4, len);
               dst.write(header);
               dst.write(buf, off, len);
            }
         }

         @Override
         public void flush() throws IOException
         {
            synchronized (dst)
            {
               if (!this.open)
                  throw new EOFException("stream closed");
               dst.flush();
            }
         }

         @Override
         public void close() throws IOException
         {
            synchronized (dst)
            {
               if (!this.open)
                  throw new EOFException("stream closed");
               this.open = false;

               PrimIO.writeInt(header, 4, CLOSE);
               dst.write(header);
               dst.flush();
            }
         }
      };
   }
}