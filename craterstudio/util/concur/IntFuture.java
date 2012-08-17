/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

import craterstudio.util.HighLevel;

public class IntFuture
{
   private boolean      waiting;
   private int           result;
   private Exception    error;
   private final Object lock;

   public IntFuture()
   {
      this.waiting = true;
      this.lock = new Object();
   }

   public boolean isDone()
   {
      synchronized (this.lock)
      {
         return !this.waiting;
      }
   }

   public int peek(int defaultValue)
   {
      synchronized (this.lock)
      {
         if (this.waiting)
         {
            return defaultValue;
         }

         if (this.error != null)
            throw new IllegalStateException("future error", this.error);
         return this.result;
      }
   }

   public int get()
   {
      synchronized (this.lock)
      {
         while (this.waiting)
         {
            HighLevel.wait(this.lock);
         }

         if (this.error != null)
            throw new IllegalStateException("future error", this.error);
         return this.result;
      }
   }

   public void set(int result)
   {
      synchronized (this.lock)
      {
         if (!this.waiting)
            throw new IllegalStateException("future already set");

         this.result = result;
         this.waiting = false;
         this.lock.notifyAll();
      }
   }

   public void error(Exception error)
   {
      if (error == null)
         throw new NullPointerException();

      synchronized (this.lock)
      {
         if (!this.waiting)
            throw new IllegalStateException("future already set");

         this.error = error;
         this.waiting = false;
         this.lock.notifyAll();
      }
   }
}