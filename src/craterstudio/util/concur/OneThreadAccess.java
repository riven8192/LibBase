/*
 * Created on 1 dec 2008
 */

package craterstudio.util.concur;

public class OneThreadAccess
{
   private final Thread thread;

   public OneThreadAccess()
   {
      this(Thread.currentThread());
   }

   public OneThreadAccess(Thread thread)
   {
      this.thread = thread;
   }

   public void check()
   {
      if (this.thread != Thread.currentThread())
      {
         throw new IllegalStateException("This thread must not access this resource");
      }
   }
}
