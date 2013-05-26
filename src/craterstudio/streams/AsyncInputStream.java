/*
 * Created on 15 okt 2008
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.InputStream;

import craterstudio.util.concur.ConcurrentQueue;

public class AsyncInputStream extends InputStream
{
   final InputStream             in;
   final ConcurrentQueue<byte[]> queue;
   volatile IOException          caught;

   public AsyncInputStream(InputStream in)
   {
      this.in = in;
      this.queue = new ConcurrentQueue<byte[]>(false);

      new Thread(new Runnable()
      {
         @Override
         public void run()
         {
            InputStream in = AsyncInputStream.this.in;
            byte[] buffer = new byte[8 * 1024];

            try
            {
               while (true)
               {
                  int bytes = in.read(buffer, 0, buffer.length);
                  if (bytes == -1)
                     break;

                  byte[] data = new byte[bytes];
                  System.arraycopy(buffer, 0, data, 0, bytes);
                  AsyncInputStream.this.queue.produce(data);
               }
            }
            catch (IOException exc)
            {
               AsyncInputStream.this.caught = exc;
            }
         }
      }).start();
   }

   @Override
   public int available() throws IOException
   {
      byte[] data = this.queue.peek();
      if (data == null)
         return 0;
      return data.length;
   }

   @Override
   public int read() throws IOException
   {
      byte[] dst = new byte[1];
      this.read(dst, 0, 1);
      return dst[0] & 0xFF;
   }

   @Override
   public int read(byte[] buf) throws IOException
   {
      return this.read(buf, 0, buf.length);
   }

   @Override
   public int read(byte[] buf, int off, int len) throws IOException
   {
      if (this.queue.isEmpty() && this.caught != null)
         throw this.caught;

      byte[] data = this.queue.consume();

      if (data.length > len)
      {
         byte[] padding = new byte[data.length - len];
         System.arraycopy(data, 0, buf, off, len);
         System.arraycopy(data, len, padding, 0, padding.length);
         this.queue.produceFirst(padding);
         return len;
      }

      System.arraycopy(data, 0, buf, off, data.length);
      return data.length;
   }

   @Override
   public long skip(long n) throws IOException
   {
      long n0 = n;
      while (true)
      {
         if (this.caught != null)
            throw this.caught;

         byte[] data = this.queue.peek();
         if (data == null || data.length > n)
            return n0 - n;

         this.queue.poll();
         n -= data.length;
      }
   }

   @Override
   public void close() throws IOException
   {
      this.in.close();
   }
}
