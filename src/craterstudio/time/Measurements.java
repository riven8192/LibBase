/*
 * Created on 23 apr 2010
 */

package craterstudio.time;

import java.util.Arrays;

public class Measurements
{
   private static final long self_time;

   static
   {
      final int runs = 8;
      final int iterations = 1024;

      long selftime = -1L;
      for (int k = 0; k < runs; k++)
      {
         long t0 = System.nanoTime();
         for (int i = 0; i < iterations; i++)
            System.nanoTime();
         long t1 = System.nanoTime();
         selftime = (t1 - t0) / (iterations + 2);
      }
      System.out.println(Measurements.class.getSimpleName() + ".selftime: " + selftime);
      self_time = selftime;
   }

   private final long[]      slots;
   private int               offset;
   private boolean           dirty;

   public Measurements(int slotCount)
   {
      this.slots = new long[slotCount];
      this.offset = 0;
      this.dirty = true;
   }

   public void addNanos(long time)
   {
      time -= self_time * 2; // assuming System.nanoTime() is called twice
      this.slots[this.offset % this.slots.length] = time;
      this.offset += 1;
      this.dirty = true;
   }

   public void addMicros(long time)
   {
      this.addNanos(time * 1000L);
   }

   public void addMillis(long time)
   {
      this.addNanos(time * 1000000L);
   }

   public long min()
   {
      this.update();
      return this.slots[0];
   }

   public long max()
   {
      this.update();
      return this.slots[this.lastIndex()];
   }

   public long avg()
   {
      this.update();
      int end = this.lastIndex();
      long sum = 0;
      for (int i = 0; i < end; i++)
         sum += this.slots[i];
      return (long) (sum / (double) end);
   }

   public double avg95()
   {
      this.update();
      int end = Math.max(1, (int) (this.lastIndex() * 0.95));
      long sum = 0;
      for (int i = 0; i < end; i++)
         sum += this.slots[i];
      return (double) sum / end;
   }

   public long typical()
   {
      this.update();
      return this.slots[this.lastIndex() / 2];
   }

   //

   private void update()
   {
      if (this.offset == 0)
         throw new IllegalStateException();
      if (!this.dirty)
         return;
      this.dirty = false;

      Arrays.sort(this.slots, 0, this.lastIndex() + 1);
   }

   private int lastIndex()
   {
      return Math.min(this.offset, this.slots.length) - 1;
   }

   public String toString()
   {
      long min = this.min();
      long max = this.max();
      long avg = this.avg();
      long typ = this.typical();

      int shifts = 0;
      while (min > 3 * 1000L)
      {
         min /= 1000L;
         max /= 1000L;
         avg /= 1000L;
         typ /= 1000L;
         shifts++;
      }
      return this.getClass().getSimpleName() + "[" + names[shifts] + ": typical=" + typ + ", avg=" + avg + ", min=" + min + ", max=" + max + "]";
   }

   private static final String[] names = new String[] { "nanos", "miscros", "millis", "seconds" };
}
