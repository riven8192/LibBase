/*
 * Created on 27-mei-2006
 */

package craterstudio.time;

import java.util.concurrent.TimeUnit;

public class Profiler
{
   /**
    * FIELDS
    */

   private boolean running, dirty;
   private long    duration, start, last;
   private int     runs;

   /**
    * START / STOP
    */

   public final void start()
   {
      if (running)
         dirty = true;
      start = System.nanoTime();
      runs += 1;
   }

   public final void stop()
   {
      if (!running)
         dirty = true;
      last = System.nanoTime() - start;
      duration += last;
   }

   public final int runs()
   {
      return this.runs();
   }

   /**
    * LAST DURATION
    */

   public final long lastDuration(TimeUnit unit)
   {
      return unit.convert(last, TimeUnit.NANOSECONDS);
   }

   public final void printLastDuration(String name, TimeUnit unit)
   {
      System.out.println(name + ": " + this.lastDuration(unit) + desc(unit));
   }

   /**
    * TOTAL DURATION
    */

   public final long totalDuration(TimeUnit unit)
   {
      long v = duration;

      if (running)
         v += (System.nanoTime() - start);

      return unit.convert(v, TimeUnit.NANOSECONDS);
   }

   public final void printTotalDuration(String name, TimeUnit unit)
   {
      System.out.println(name + ": " + this.totalDuration(unit) + desc(unit));
   }

   //

   private final String desc(TimeUnit unit)
   {
      if (unit == TimeUnit.NANOSECONDS)
         return "ns";
      if (unit == TimeUnit.MICROSECONDS)
         return "us";
      if (unit == TimeUnit.MILLISECONDS)
         return "ms";
      if (unit == TimeUnit.SECONDS)
         return "s";

      return "?";
   }

   /**
    * RESET
    */

   public final void reset()
   {
      running = false;
      duration = 0L;
      dirty = false;
   }

   public final boolean isDirty()
   {
      return dirty;
   }
}