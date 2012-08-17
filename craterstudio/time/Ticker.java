/*
 * Created on 24-okt-2004
 */
package craterstudio.time;

import craterstudio.util.HighLevel;

public class Ticker
{
   public static final long[] HZ_25  = new long[] { 40 };
   public static final long[] HZ_30  = new long[] { 33, 34, 33 };
   public static final long[] HZ_40  = new long[] { 25 };
   public static final long[] HZ_50  = new long[] { 20 };
   public static final long[] HZ_60  = new long[] { 16, 17, 16 };
   public static final long[] HZ_75  = new long[] { 13, 14, 13 };
   public static final long[] HZ_80  = new long[] { 12, 13 };
   public static final long[] HZ_100 = new long[] { 10 };
   public static final long[] HZ_120 = new long[] { 8, 9, 8 };
   public static final long[] HZ_150 = new long[] { 7, 8 };
   public static final long[] HZ_200 = new long[] { 5 };

   //

   private final long[]       interval;

   private final float        duration;

   public Ticker(long[] interval)
   {
      this.interval = interval;

      long sum = 0;
      for (int i = 0; i < interval.length; i++)
         sum += interval[i];
      duration = 0.001F * sum / interval.length;
   }

   /**
    * SET ON
    */

   private Tickable onTick, onFreeTime, onException, onQuit;

   public final void setOnTick(Tickable r)
   {
      this.onTick = r;
   }

   public final void setOnFreeTime(Tickable r)
   {
      this.onFreeTime = r;
   }

   public final void setOnException(Tickable r)
   {
      this.onException = r;
   }

   public final void setOnQuit(Tickable r)
   {
      this.onQuit = r;
   }

   /**
    * DURATION
    */

   public final float getDuration()
   {
      return duration;
   }

   /**
    * START
    */

   public final void start()
   {
      if (running)
      {
         throw new IllegalStateException("Already running.");
      }

      running = true;

      loop();
   }

   public final void stop()
   {
      running = false;
   }

   /**
    * LOOP
    */

   private final void loop()
   {
      int i = 0;
      long nextTick = System.nanoTime() / 1000000L;

      try
      {
         while (running)
         {
            // perform tick
            if (onTick != null)
            {
               onTick.tick();
            }

            // set next tick
            nextTick += interval[++i % interval.length];

            // askdjf
            if (onFreeTime != null)
            {
               // nextTick is in the future, so we have time for other things
               if (nextTick > System.nanoTime() / 1000000L)
               {
                  onFreeTime.tick();
               }
            }

            // sleep until next tick
            long t0 = System.nanoTime() / 1000000L;
            if (nextTick - System.nanoTime() / 1000000L > 0)
               HighLevel.sleep(nextTick - System.nanoTime() / 1000000L);
            long t1 = System.nanoTime() / 1000000L;
            idleTime += t1 - t0;
         }
      }
      catch (Exception exc)
      {
         exc.printStackTrace();

         fatalException = exc;

         if (onException != null)
         {
            onException.tick();
         }
      }

      if (onQuit != null)
      {
         onQuit.tick();
      }
   }

   /**
    * IDLE TIME
    */

   private long idleTime;

   public final long getIdleTime()
   {
      long tmp = idleTime;
      idleTime = 0;
      return tmp;
   }

   /**
    * EXCEPTION
    */

   private Exception fatalException;

   public Exception getFatalException()
   {
      return fatalException;
   }

   /**
    * TICK
    */

   private long tick = 0L;

   public final void setTick(long tick)
   {
      this.tick = tick;
   }

   public final long getTick()
   {
      return tick;
   }

   /**
    * RUNNING
    */

   private boolean running = false;

   public final boolean isRunning()
   {
      return running;
   }

}