/*
 * Created on Sep 3, 2008
 */

package craterstudio.util.concur;

public class RunnablePipeline implements Runnable
{
   private final ConcurrentQueue<Runnable> pending;

   public RunnablePipeline(ConcurrentQueue<Runnable> pending)
   {
      this.pending = pending;
   }

   @Override
   public void run()
   {
      Runnable task;

      while ((task = this.pending.consume()) != null)
      {
         try
         {
            task.run();
         }
         catch (Throwable t)
         {
            t.printStackTrace();
         }
      }
   }
}
