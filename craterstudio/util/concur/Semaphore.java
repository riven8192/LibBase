/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

import craterstudio.util.HighLevel;

public class Semaphore
{
   private int          available;
   private int          poolSize;
   private final Object lock;

   public Semaphore(int poolSize)
   {
      if (poolSize < 0)
      {
         throw new IllegalStateException();
      }

      this.available = poolSize;
      this.poolSize = poolSize;
      this.lock = new Object();
   }

   //

   public Semaphore aquire()
   {
      return this.aquire(1);
   }

   public Semaphore aquire(int amount)
   {
      if (amount < 0)
      {
         throw new IllegalStateException();
      }

      synchronized (this.lock)
      {
         while (this.available < amount)
         {
            HighLevel.wait(this.lock);
         }

         this.available -= amount;

         this.lock.notifyAll();
      }
      
      return this;
   }

   public Semaphore release()
   {
      return this.release(1);
   }

   public Semaphore release(int amount)
   {
      if (amount < 0)
      {
         throw new IllegalStateException();
      }

      synchronized (this.lock)
      {
         if (this.available + amount > this.poolSize)
            throw new IllegalStateException("released more than aquired");
         this.available += amount;

         this.lock.notifyAll();
      }
      
      return this;
   }

   //

   public int peekAvailable()
   {
      synchronized (this.lock)
      {
         return this.available;
      }
   }

   //

   public void setPoolSize(int poolSize)
   {
      synchronized (this.lock)
      {
         if (poolSize <= 0)
         {
            throw new IllegalStateException();
         }

         this.adjustPoolSize(poolSize - this.poolSize);
      }
   }

   public int getPoolSize()
   {
      synchronized (this.lock)
      {
         return this.poolSize;
      }
   }

   public int adjustPoolSize(int amount)
   {
      synchronized (this.lock)
      {
         // shrink once there are enough resources available
         if (amount < 0)
         {
            int shrinkAmount = -amount;
            while (shrinkAmount > this.available)
            {
               HighLevel.wait(this.lock);
            }
         }

         this.available += amount;
         this.poolSize += amount;

         this.lock.notifyAll();

         return this.poolSize;
      }
   }
}