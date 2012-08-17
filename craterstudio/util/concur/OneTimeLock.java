/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

import craterstudio.util.HighLevel;

public class OneTimeLock
{
   private volatile boolean locked;
   private final Object     lock;

   public OneTimeLock()
   {
      this.locked = true;
      this.lock = new Object();
   }

   public void waitFor()
   {
      synchronized (this.lock)
      {
         while (this.locked)
         {
            HighLevel.wait(this.lock);
         }
      }
   }

   public void yieldFor()
   {
      while (this.locked)
      {
         Thread.yield();
      }
   }

   public boolean isLocked()
   {
      synchronized (this.lock)
      {
         return this.locked;
      }
   }

   public void release()
   {
      synchronized (this.lock)
      {
         if (!this.locked)
            throw new IllegalStateException("already released");
         this.locked = false;

         this.lock.notifyAll();
      }
   }
}
