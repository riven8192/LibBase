/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

public class UnfairLock
{
   private OneTimeLock  current;
   private final Object lock;

   public UnfairLock()
   {
      this.current = new OneTimeLock();
      this.current.release();
      this.lock = new Object();
   }

   public OneTimeLock aquire()
   {
      OneTimeLock oneTimeLock = new OneTimeLock();

      synchronized (this.lock)
      {
         // only the first thread gets here, and waits.
         // all others are waiting on the 'this.lock'
         // which the first thread holds, despite the 'waitFor'

         // so this 'unfair' lock threats the first
         // thread that calls aquire() with priority

         this.current.waitFor();
         this.current = oneTimeLock;
      }

      return oneTimeLock;
   }
}