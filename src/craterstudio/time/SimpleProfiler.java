/*
 * Created on 15 sep 2008
 */

package craterstudio.time;

import craterstudio.util.HighLevel;

public class SimpleProfiler
{
   public static boolean VERBOSE            = !true;

   private long          init, last, memUsed;
   public boolean        measureMemoryUsage = false;

   public SimpleProfiler start()
   {
      this.init = this.last = this.now();
      if (this.measureMemoryUsage)
      {
         System.gc();
         this.memUsed = HighLevel.memUsed();
      }
      return this;
   }

   public SimpleProfiler measure(String msg)
   {
      long now = this.now();
      long took = now - this.last;
      if (this.measureMemoryUsage)
      {
         System.gc();
         long memUsed = HighLevel.memUsed();
         long delta = (memUsed - this.memUsed) / 1024;
         if (VERBOSE)
         {
            System.out.println(msg + " took: " + took + "ms (delta: " + delta + "KB / " + memUsed / 1024 + "KB)");
         }
         this.memUsed = memUsed;
      }
      else
      {
         if (VERBOSE)
         {
            System.out.println(msg + " took: " + took + "ms");
         }
      }
      this.last = now;
      return this;
   }

   public void total(String msg)
   {
      long now = this.now();
      long took = now - this.init;
      if (VERBOSE)
      {
         System.out.println(msg + " took: " + took + "ms");
      }
   }

   public boolean useNanoTimer = true;

   private final long now()
   {
      if (useNanoTimer)
         return System.nanoTime() / 1000000L;
      return System.currentTimeMillis();
   }
}
