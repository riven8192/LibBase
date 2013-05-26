/*
 * Created on 24-apr-2006
 */

package craterstudio.time;

public class HiResTicker
{
   final double   interval;
   final Runnable task;
   boolean        running;

   public HiResTicker(double interval, Runnable task)
   {
      this.interval = interval;
      this.task = task;
   }

   public final void start()
   {
      running = true;

      Runnable loop = new Runnable()
      {
         public void run()
         {
            double tNext = System.nanoTime();

            while (running)
            {
               double t1 = System.nanoTime();

               if (t1 < tNext)
               {
                  Thread.yield();
                  continue;
               }

               tNext += interval;
               task.run();
            }
         }
      };

      Thread thread = new Thread(loop, "hi-res-ticker");
      thread.setDaemon(false);
      thread.start();
   }

   public final void stop()
   {
      running = false;
   }
}
