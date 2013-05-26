/*
 * Created on Jul 20, 2008
 */

package craterstudio.time;

import java.util.Arrays;

public class PerfMon
{
   private final long[] durations;
   private final long   selfTime;
   private int          offset, records;
   private boolean      isActive;

   public PerfMon(int samples)
   {
      this.durations = new long[samples];
      this.selfTime = this.calcSelfTime();
      this.offset = 0;
      this.isActive = false;
   }

   private final long calcSelfTime()
   {
      int runs = 1024;

      for (int i = 0; i < runs; i++)
         System.nanoTime();

      long t0 = System.nanoTime();
      for (int i = 0; i < runs; i++)
         System.nanoTime();
      long t1 = System.nanoTime();

      return (t1 - t0) / (runs + 2);
   }

   public void reset()
   {
      if (isActive)
         throw new IllegalStateException();
      offset = records = 0;
   }

   public void begin()
   {
      if (isActive)
         throw new IllegalStateException();
      isActive = true;

      durations[offset] = System.nanoTime();
   }

   public void end()
   {
      if (!isActive)
         throw new IllegalStateException();
      isActive = false;

      durations[offset] = System.nanoTime() - durations[offset] - this.selfTime;

      offset = (offset + 1) % durations.length;
      records++;
   }

   public long min()
   {
      long[] copy = this.sort();
      return copy[0];
   }

   public long nominal()
   {
      long[] copy = this.sort();
      return copy[copy.length / 2];
   }

   public long max()
   {
      long[] copy = this.sort();
      return copy[copy.length - 1];
   }

   private final long[] sort()
   {
      if (records == 0 || isActive)
         throw new IllegalStateException();
      long[] copy = new long[Math.min(durations.length, records)];
      System.arraycopy(durations, 0, copy, 0, copy.length);
      Arrays.sort(copy);
      return copy;
   }
}
