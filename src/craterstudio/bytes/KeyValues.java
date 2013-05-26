/*
 * Created on 25 mrt 2010
 */

package craterstudio.bytes;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

import craterstudio.io.Streams;
import craterstudio.text.Text;
import craterstudio.util.ListUtil;

public class KeyValues
{
   static class KeyValue
   {
      public final byte[] key, value;

      public KeyValue(byte[] key, byte[] value)
      {
         this.key = key;
         this.value = value;
      }
   }

   public static void main(String[] args) throws IOException
   {
      final int dataItemCount = 1024;
      final int keySize = 8;
      final int valSize = 4;
      final int bufSize = 64 * 1024;

      File f1 = new File("E:/data1.bin");
      File f2 = new File("E:/data2.bin");
      File f3 = new File("E:/data1.bin");
      File f4 = new File("E:/data2.bin");
      File f12 = new File("E:/data12.bin");
      File f34 = new File("E:/data34.bin");
      File f1234 = new File("E:/data1234.bin");

      KeyValue[] data1 = createRandomSet(dataItemCount, keySize, valSize);
      KeyValue[] data2 = createRandomSet(dataItemCount, keySize, valSize);
      KeyValue[] data3 = createRandomSet(dataItemCount, keySize, valSize);
      KeyValue[] data4 = createRandomSet(dataItemCount, keySize, valSize);

      store(data1, new FileOutputStream(f1));
      store(data2, new FileOutputStream(f2));
      store(data3, new FileOutputStream(f3));
      store(data4, new FileOutputStream(f4));

      mergeSortedKeyValueFiles(f1, f2, f12, keySize, valSize, bufSize);
      mergeSortedKeyValueFiles(f3, f4, f34, keySize, valSize, bufSize);
      mergeSortedKeyValueFiles(f12, f34, f1234, keySize, valSize, bufSize);

      KeyValue[] pairs = load(f1234, keySize, valSize, bufSize);
      for (KeyValue pair : pairs)
         System.out.println(Text.ascii(pair.key));
      System.out.println("pairs: " + pairs.length);
   }

   private static KeyValue[] createRandomSet(int elementCount, int keySize, int valSize)
   {
      KeyValue[] data = new KeyValue[elementCount];

      for (int i = 0; i < data.length; i++)
      {
         byte[] key = Text.ascii(Text.generateRandomCode(keySize));
         byte[] val = Text.ascii(Text.generateRandomCode(valSize));
         data[i] = new KeyValue(key, val);
      }

      sort(data);

      return data;
   }

   private static void store(KeyValue[] set, OutputStream out) throws IOException
   {
      for (KeyValue item : set)
      {
         out.write(item.key);
         out.write(item.value);
      }
   }

   private static KeyValue[] load(File file, int keySize, int valSize, int bufSize) throws IOException
   {
      return load(new DataInputStream(new BufferedInputStream(new FileInputStream(file), bufSize)), keySize, valSize);
   }

   private static KeyValue[] load(DataInputStream in, int keySize, int valSize) throws IOException
   {
      List<KeyValue> list = new ArrayList<KeyValue>();

      try
      {
         while (true)
         {
            KeyValue item = new KeyValue(new byte[keySize], new byte[valSize]);
            try
            {
               in.readFully(item.key);
            }
            catch (EOFException exc)
            {
               break;
            }
            in.readFully(item.value);
            list.add(item);
         }
      }
      finally
      {
         Streams.safeClose(in);
      }

      return ListUtil.toArray(KeyValue.class, list);
   }

   public static void sort(KeyValue[] data)
   {
      Arrays.sort(data, new Comparator<KeyValue>()
      {
         @Override
         public int compare(KeyValue a, KeyValue b)
         {
            return compareByteArray(a.key, b.key);
         }
      });
   }

   public static void mergeSortedKeyValueFiles(File a, File b, File dst, int keySize, int valSize, int bufSize) throws IOException
   {
      DataInputStream inA = new DataInputStream(new BufferedInputStream(new FileInputStream(a), bufSize));
      DataInputStream inB = new DataInputStream(new BufferedInputStream(new FileInputStream(b), bufSize));
      OutputStream out = new BufferedOutputStream(new FileOutputStream(dst), bufSize);

      mergeSortedKeyValues(inA, inB, out, keySize, valSize);

      Streams.safeClose(inA);
      Streams.safeClose(inB);
      Streams.safeClose(out);
   }

   public static void mergeSortedKeyValues(DataInputStream a, DataInputStream b, OutputStream out, int keySize, int valSize) throws IOException
   {
      byte[] keyA = new byte[keySize];
      byte[] keyB = new byte[keySize];
      byte[] valN = new byte[valSize];

      a.readFully(keyA);
      b.readFully(keyB);

      while (keyA != null && keyB != null)
      {
         if (compareByteArray(keyA, keyB) <= 0)
         {
            a.readFully(valN);
            out.write(keyA);
            out.write(valN);

            try
            {
               a.readFully(keyA);
            }
            catch (EOFException exc)
            {
               keyA = null;
            }
         }
         else
         {
            b.readFully(valN);
            out.write(keyB);
            out.write(valN);

            try
            {
               b.readFully(keyB);
            }
            catch (EOFException exc)
            {
               keyB = null;
            }
         }
      }

      if (keyA != null)
      {
         for (int i = 0; true; i++)
         {
            try
            {
               if (i != 0)
                  a.readFully(keyA);
               a.readFully(valN);
               out.write(keyA);
               out.write(valN);
            }
            catch (EOFException exc)
            {
               break;
            }
         }
      }

      if (keyB != null)
      {
         for (int i = 0; true; i++)
         {
            try
            {
               if (i != 0)
                  b.readFully(keyB);
               b.readFully(valN);
               out.write(keyB);
               out.write(valN);
            }
            catch (EOFException exc)
            {
               break;
            }
         }
      }
   }

   public static int compareByteArray(byte[] a, byte[] b)
   {
      for (int i = 0; i < a.length; i++)
      {
         int ai = (a[i] & 0xFF);
         int bi = (b[i] & 0xFF);
         int diff = ai - bi;
         if (diff == 0)
            continue;
         return diff;
      }
      return 0;
   }
}
