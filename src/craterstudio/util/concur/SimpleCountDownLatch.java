/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SimpleCountDownLatch
{
   private final CountDownLatch backing;

   public SimpleCountDownLatch()
   {
      this(1);
   }

   public SimpleCountDownLatch(int amount)
   {
      if (amount <= 0)
         throw new IllegalArgumentException("invalid amount: " + amount);

      this.backing = new CountDownLatch(amount);
   }

   public boolean isDone()
   {
      return (this.backing.getCount() == 0L);
   }

   public void await()
   {
      try
      {
         this.backing.await();
      }
      catch (InterruptedException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public boolean await(long timeout)
   {
      try
      {
         return this.backing.await(timeout, TimeUnit.MILLISECONDS);
      }
      catch (InterruptedException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public void countDown()
   {
      this.backing.countDown();
   }
}