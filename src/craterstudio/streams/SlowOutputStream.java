/*
 * Created on 23 mei 2011
 */

package craterstudio.streams;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import craterstudio.io.Streams;
import craterstudio.math.EasyMath;
import craterstudio.time.Clock;
import craterstudio.util.HighLevel;
import craterstudio.util.concur.SimpleBlockingQueue;

public class SlowOutputStream extends AbstractOutputStream
{
   public SlowOutputStream(OutputStream out, final int minLatency, final int maxLatency, final int batchSize, final int batchInterval)
   {
      super(out);

      new Thread(new Runnable()
      {
         @Override
         public void run()
         {
            try
            {
               while (true)
               {
                  Packet p = packets.take();
                  if (p == null)
                  {
                     break;
                  }

                  int latency = (int) EasyMath.lerp(minLatency, maxLatency, (float) Math.pow(Math.random(), 2.0));
                  while (Clock.now() - p.timestamp < latency)
                  {
                     HighLevel.sleep(1);
                  }

                  if (p.data == null)
                  {
                     SlowOutputStream.this.backing.flush();
                  }
                  else
                  {
                     do
                     {
                        byte[] toSend = Arrays.copyOf(p.data, Math.min(p.data.length, batchSize));

                        SlowOutputStream.this.backing.write(toSend);
                        System.out.println("packet.sent=" + toSend.length + " / " + p.data.length);
                        p.data = Arrays.copyOfRange(p.data, toSend.length, p.data.length);

                        HighLevel.sleep(batchInterval);
                     }
                     while (p.data.length > 0);
                  }
               }
            }
            catch (IOException exc)
            {
               exc.printStackTrace();
            }
            finally
            {
               Streams.safeClose(SlowOutputStream.this.backing);
            }
         }
      }).start();
   }

   static class Packet
   {
      long   timestamp;
      byte[] data;
   }

   final SimpleBlockingQueue<Packet> packets = new SimpleBlockingQueue<Packet>();

   @Override
   public void write(byte[] buf, int off, int len) throws IOException
   {
      Packet packet = new Packet();
      packet.timestamp = Clock.now();
      packet.data = Arrays.copyOfRange(buf, off, len);
      this.packets.put(packet);
   }

   @Override
   public void flush() throws IOException
   {
      Packet packet = new Packet();
      packet.timestamp = Clock.now();
      packet.data = null;
      this.packets.put(packet);
   }

   @Override
   public void close() throws IOException
   {
      this.packets.put(null);
   }
}
