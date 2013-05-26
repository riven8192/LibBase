/*
 * Created on 5 okt 2010
 */

package craterstudio.util.concur;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.concurrent.Executor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import craterstudio.misc.Debug;
import craterstudio.util.HighLevel;

public class SimpleThreadPool implements Executor
{
   final ThreadPoolExecutor            pool;
   final SimpleBlockingQueue<Runnable> pump;

   public SimpleThreadPool(String name, int minWorkers, int maxWorkers)
   {
      this(name, minWorkers, maxWorkers, 60 * 1000, -1L);
   }

   public SimpleThreadPool(final String name, int minWorkers, int maxWorkers, long timeout, final long stackSize)
   {
      minWorkers = Math.min(minWorkers, maxWorkers);

      this.pump = new SimpleBlockingQueue<Runnable>();
      this.pool = new ThreadPoolExecutor(minWorkers, maxWorkers, timeout, TimeUnit.MILLISECONDS, new SynchronousQueue<Runnable>(), customStacksizeThreadFactory(name, stackSize));

      new Thread(new Runnable()
      {
         @Override
         public void run()
         {
            for (Runnable task; (task = SimpleThreadPool.this.pump.take()) != null;)
            {
               SimpleThreadPool.this.pool.execute(task);
            }
         }
      }).start();
   }

   @Override
   public void execute(Runnable command)
   {
      if (command == null)
         throw new NullPointerException();
      this.pump.put(command);
   }

   public void shutdown(boolean wait)
   {
      this.pump.put(null);

      while (!this.pump.isEmpty())
         HighLevel.sleep(10);

      this.pool.shutdown();

      if (wait)
         while (!this.pool.isTerminated())
            HighLevel.sleep(10);
   }

   static ThreadFactory customStacksizeThreadFactory(final String name, final long stackSize)
   {
      return new ThreadFactory()
      {
         private final AtomicLong counter = new AtomicLong();

         @Override
         public Thread newThread(final Runnable task)
         {
            // System.out.println("SimpleThreadPool[" + name + "].newThread(" + stackSize + ")");

            String tname = "SimpleThreadPool-" + name + "-thread-" + this.counter.incrementAndGet();

            Runnable wrapper = new Runnable()
            {
               @Override
               public void run()
               {
                  final long id = Thread.currentThread().getId();
                  final String name = Thread.currentThread().getName();

                  Debug.log("Thread#" + id + " '" + name + "' started");

                  try
                  {
                     task.run();
                  }
                  catch (Throwable t)
                  {
                     t.printStackTrace();
                  }
                  finally
                  {
                     if (tmxb == null)
                        return;

                     long ms = tmxb.getThreadCpuTime(id) / 1000000L;

                     Debug.log("Thread#" + id + " '" + name + "' terminated (" + ms + "ms)");
                  }
               }
            };

            if (stackSize <= 0)
               return new Thread(wrapper, tname);
            return new Thread(null, wrapper, tname, stackSize);
         }
      };
   }

   // ----

   final static ThreadMXBean tmxb;
   static
   {
      ThreadMXBean bean;
      try
      {
         bean = ManagementFactory.getThreadMXBean();
         bean.setThreadCpuTimeEnabled(true);
      }
      catch (Exception exc)
      {
         bean = null;
      }

      tmxb = bean;
   }
}
