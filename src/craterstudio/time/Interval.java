/*
 * Created on 16-mei-2005
 */
package craterstudio.time;

import craterstudio.util.HighLevel;

public class Interval
{
   public static Interval create(long delay, long interval)
   {
      return new Interval(interval, Clock.now() + delay - interval);
   }

   private long timestamp, interval;

   public Interval(long interval)
   {
      this(interval, Clock.now());
   }

   public Interval(long interval, long timestamp)
   {
      this.interval = interval;
      this.timestamp = timestamp;
   }

   public final long getInterval()
   {
      return this.interval;
   }

   public final long getTimeLeft()
   {
      long next = this.timestamp + this.interval;
      long left = next - Clock.now();
      return left;
   }

   public final void stepOver()
   {
      long now = Clock.now();
      while (this.timestamp < now)
         this.timestamp += this.interval;
   }

   public final boolean hasPassedAndStep()
   {
      boolean passed = Clock.now() >= (this.timestamp + this.interval);
      if (passed)
         this.timestamp += this.interval;
      return passed;
   }

   public final boolean hasPassedAndStepOver()
   {
      boolean passed = this.hasPassedAndStep();
      if (passed)
         this.stepOver();
      return passed;
   }
   
   public final void waitFor()
   {
      while(!this.hasPassedAndStep())
      {
         HighLevel.sleep(1);
      }
   }
}