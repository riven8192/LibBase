/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

import java.util.concurrent.atomic.AtomicInteger;

public class Barrier
{
   private final AtomicInteger        pending, cumulative;
   private final SimpleCountDownLatch latch;

   public Barrier()
   {
      this(0);
   }

   public Barrier(int registrations)
   {
      this.pending = new AtomicInteger(registrations);
      this.cumulative = new AtomicInteger(registrations);
      this.latch = new SimpleCountDownLatch();
   }

   public void register()
   {
      if (this.latch.isDone())
      {
         throw new IllegalStateException("already reached barrier");
      }

      this.pending.incrementAndGet();
      this.cumulative.incrementAndGet();
   }

   public void notifyAwait()
   {
      if (!this.notifyDone())
      {
         this.latch.await();
      }
   }

   public boolean notifyDone()
   {
      int got = this.pending.decrementAndGet();
      if (got < 0)
         throw new IllegalStateException();
      if (got != 0)
         return false;

      this.latch.countDown();
      return true;
   }

   //

   public boolean isDone()
   {
      return this.latch.isDone();
   }

   public void waitForAll()
   {
      if (this.pending.intValue() > 0)
      {
         this.latch.await();
      }
   }

   public int countPending()
   {
      return Math.max(0, this.pending.intValue());
   }

   public int countTotal()
   {
      return this.cumulative.intValue();
   }
}
