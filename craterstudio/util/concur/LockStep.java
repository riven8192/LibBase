/*
 * Created on 1 sep 2010
 */

package craterstudio.util.concur;

public class LockStep
{
   public LockStep()
   {
      this.curr = new OneTimeLock();
      this.next = null;
   }

   private OneTimeLock curr;
   private OneTimeLock next;

   public void signalWaitFor()
   {
      OneTimeLock curr;
      OneTimeLock next;
      
      synchronized (this)
      {
         curr = this.curr;
         next = this.next;

         this.curr = next;
         this.next = new OneTimeLock();
      }
      
      curr.release();
      next.waitFor();
   }
}
