/*
 * Created on Aug 12, 2009
 */

package craterstudio.misc;

import craterstudio.util.concur.OneThreadAccess;

public class TaskProfiler
{
   private final OneThreadAccess access;
   private boolean               measuring;
   private long                  started;
   private long                  total;

   public TaskProfiler()
   {
      this.access = new OneThreadAccess();
   }

   private long now()
   {
      return System.nanoTime();
   }

   public void reset()
   {
      this.access.check();
      
      this.total = 0L;
   }

   public void start()
   {
      this.access.check();

      if (this.measuring)
         throw new IllegalStateException();
      this.measuring = true;

      this.started = this.now();
   }

   public void stop()
   {
      this.access.check();

      if (!this.measuring)
         throw new IllegalStateException();
      this.measuring = false;

      this.total += (this.now() - this.started);
   }

   public long total()
   {
      return this.total;
   }
}