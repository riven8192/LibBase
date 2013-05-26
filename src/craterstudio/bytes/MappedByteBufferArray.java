/*
 * Created on 11 okt 2010
 */

package craterstudio.bytes;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.util.ArrayList;
import java.util.List;

public class MappedByteBufferArray
{
   public static void main(String[] args) throws IOException
   {
      // 200GB
      long len = 200L * 1024 * 1024 * 1024;
      File file = new File("C:\\huge.dat");

      if (file.length() != len)
      {
         RandomAccessFile raf = new RandomAccessFile(file, "rw");
         raf.setLength(len);
         raf.close();
      }

      long t0 = System.currentTimeMillis();
      MappedByteBufferArray array;
      array = new MappedByteBufferArray(file, MapMode.READ_WRITE);
      long t1 = System.currentTimeMillis();

      System.out.println("mappings: " + array.mapping.length + ", took: " + (t1 - t0) + "ms");
   }

   // ---

   public final MappedByteBuffer[] mapping;

   public MappedByteBufferArray(File file, MapMode mode) throws IOException
   {
      this(file, mode, Integer.MAX_VALUE);
   }

   public MappedByteBufferArray(File file, MapMode mode, int chunkSize) throws IOException
   {
      RandomAccessFile raf = new RandomAccessFile(file, "rw");
      long length = raf.length();
      FileChannel chan = raf.getChannel();

      List<MappedByteBuffer> maps = new ArrayList<MappedByteBuffer>();

      long offset = 0;
      while (offset < length)
      {
         long chunk = Math.min(length - offset, chunkSize);
         MappedByteBuffer map;
         map = chan.map(mode, offset, chunk);
         offset += map.capacity();
         maps.add(map);
      }
      raf.close();

      this.mapping = maps.toArray(new MappedByteBuffer[maps.size()]);
   }
}
