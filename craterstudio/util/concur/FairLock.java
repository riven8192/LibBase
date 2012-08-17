/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

import craterstudio.util.HighLevel;

public class FairLock
{
   private final ConcurrentQueue<OneTimeLock> queue;

   public FairLock()
   {
      this.queue = new ConcurrentQueue<OneTimeLock>(true);
   }

   public OneTimeLock aquire()
   {
      OneTimeLock oneTimeLock = new OneTimeLock();

      // wait for turn
      synchronized (this.queue.mutex())
      {
         this.queue.produce(oneTimeLock);

         while (this.queue.peek() != oneTimeLock)
         {
            HighLevel.wait(this.queue.mutex());
         }

         if (this.queue.poll() != oneTimeLock)
         {
            throw new IllegalStateException("paranoid");
         }
      }

      return oneTimeLock;
   }
}