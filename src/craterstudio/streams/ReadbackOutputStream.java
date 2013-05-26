/*
 * Created on Mar 26, 2008
 */

package craterstudio.streams;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import craterstudio.io.FileUtil;
import craterstudio.util.concur.SimpleBlockingQueue;

public class ReadbackOutputStream extends OutputStream
{
   final StorageStrategy storageStrategy;

   public ReadbackOutputStream()
   {
      this.storageStrategy = new RamStorageStrategy();
   }

   public ReadbackOutputStream(File base, String prefix, String postfix)
   {
      this.storageStrategy = new FileStorageStrategy(base, prefix, postfix);
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
      if (this.writeClosed)
      {
         throw new IOException("stream closed");
      }

      storageStrategy.store(buf, off, len);
   }

   private boolean createdInputStream = false;

   public InputStream createInputStream()
   {
      synchronized (this)
      {
         if (this.createdInputStream)
            throw new IllegalStateException("already created InputStream");
         this.createdInputStream = true;
      }

      return new ChainedInputStream()
      {
         @Override
         protected InputStream nextStream()
         {
            byte[] data = storageStrategy.load(true);
            if (data == null)
               return null;
            return new ByteArrayInputStream(data);
         }
      };
   }

   @Override
   public void flush() throws IOException
   {
      // flushing doesn't make any sense

      if (this.writeClosed)
      {
         throw new EOFException("stream closed");
      }
   }

   private volatile boolean writeClosed;

   @Override
   public void close() throws IOException
   {
      this.writeClosed = true;

      storageStrategy.signalEndOfData();
   }

   @Override
   protected void finalize() throws Throwable
   {
      super.finalize();

      storageStrategy.cleanup();
   }

   interface StorageStrategy
   {
      public void store(byte[] buf, int off, int len);

      public void signalEndOfData();

      public byte[] load(boolean waitFor);

      public void cleanup();
   }

   class RamStorageStrategy implements StorageStrategy
   {
      final SimpleBlockingQueue<byte[]> queue = new SimpleBlockingQueue<byte[]>();

      @Override
      public void store(byte[] buf, int off, int len)
      {
         byte[] data = Arrays.copyOfRange(buf, off, off + len);

         queue.put(data);
      }

      @Override
      public void signalEndOfData()
      {
         queue.put(null);
      }

      @Override
      public byte[] load(boolean waitFor)
      {
         return waitFor ? queue.take() : queue.poll();
      }

      @Override
      public void cleanup()
      {
         this.queue.clear();
      }
   }

   class FileStorageStrategy implements StorageStrategy
   {
      final SimpleBlockingQueue<File> queue = new SimpleBlockingQueue<File>();

      private final File              base;
      private final String            prefix, postfix;

      public FileStorageStrategy(File base, String prefix, String postfix)
      {
         this.base = base;
         this.prefix = prefix;
         this.postfix = postfix;
      }

      @Override
      public void store(byte[] buf, int off, int len)
      {
         try
         {
            byte[] data = Arrays.copyOfRange(buf, off, off + len);

            File file;
            if (this.base == null)
            {
               file = File.createTempFile(prefix, postfix);
            }
            else
            {
               String id = Long.toHexString(System.nanoTime()) + Long.toHexString(System.currentTimeMillis());
               file = new File(this.base, prefix + id + postfix);
            }

            FileUtil.writeFile(file, data);
            file.deleteOnExit();

            queue.put(file);
         }
         catch (IOException exc)
         {
            throw new RuntimeException(exc);
         }
      }

      @Override
      public void signalEndOfData()
      {
         queue.put(null);
      }

      @Override
      public byte[] load(boolean waitFor)
      {
         File file = waitFor ? queue.take() : queue.poll();
         if (file == null)
            return null;

         byte[] data = FileUtil.readFile(file);
         if (!file.delete())
            throw new IllegalStateException(new IOException("could not delete chunk"));
         if (data == null)
            throw new IllegalStateException(new IOException("could not read chunk"));
         return data;
      }

      @Override
      public void cleanup()
      {
         while (true)
         {
            File file = this.queue.poll();
            if (file == null)
               break;
            file.delete();
         }
      }
   }
}