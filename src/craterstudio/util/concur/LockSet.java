/*
 * Created on 30 aug 2010
 */

package craterstudio.util.concur;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;

public class LockSet implements Lock
{
   private final Lock[] locks;

   public LockSet(Lock... locks)
   {
      this.locks = locks;
   }

   @Override
   public Condition newCondition()
   {
      throw new UnsupportedOperationException();
   }

   @Override
   public void lock()
   {
      while (!this.tryLock())
      {
         // spin!
      }
   }

   public void lock(long retryDelay)
   {
      while (!this.tryLock())
      {
         try
         {
            Thread.sleep(retryDelay);
         }
         catch (InterruptedException exc)
         {
            // ignore
         }
      }
   }

   @Override
   public boolean tryLock()
   {
      this.checkNotLocked();

      for (int i = 0; i < this.locks.length; i++)
         if (!this.locks[i].tryLock())
            return this.rollback(i);
      return this.success();
   }

   @Override
   public boolean tryLock(long time, TimeUnit unit) throws InterruptedException
   {
      this.checkNotLocked();

      long nanos = unit.toNanos(time);
      long started = System.nanoTime();
      long expires = started + nanos;

      for (int i = 0; i < locks.length; i++)
      {
         try
         {
            long remaining = expires - System.nanoTime();
            if (!this.locks[i].tryLock(remaining, TimeUnit.NANOSECONDS))
               return this.rollback(i);
         }
         catch (InterruptedException exc)
         {
            this.rollback(i);
            throw exc;
         }
      }

      return this.success();
   }

   @Override
   public void lockInterruptibly() throws InterruptedException
   {
      this.checkNotLocked();

      for (int i = 0; i < this.locks.length; i++)
      {
         try
         {
            this.locks[i].lockInterruptibly();
         }
         catch (InterruptedException exc)
         {
            this.rollback(i);
            throw exc;
         }
      }

      this.success();
   }

   @Override
   public void unlock()
   {
      this.checkLocked();

      for (int i = 0; i < this.locks.length; i++)
         this.locks[i].unlock();
      this.isLocked = false;
   }

   // state

   private boolean isLocked;

   private final void checkLocked()
   {
      if (!this.isLocked)
         throw new IllegalStateException();
   }

   private final void checkNotLocked()
   {
      if (this.isLocked)
         throw new IllegalStateException();
   }

   private final boolean success()
   {
      return (this.isLocked = true); // assignment is correct
   }

   private final boolean rollback(int i)
   {
      while (--i >= 0)
         this.locks[i].unlock();
      return false;
   }
}