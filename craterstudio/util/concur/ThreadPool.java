/*
 * Created on 21 jan 2008
 */

package craterstudio.util.concur;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadPool
{
   final AtomicInteger busyWorkers;
   final AtomicInteger idleWorkers;
   final AtomicInteger aliveWorkers;
   volatile int        minIdleWorkers;
   volatile int        maxBusyWorkers;

   public ThreadPool(int max)
   {
      this(Math.min(max, Runtime.getRuntime().availableProcessors()), max);
   }

   public ThreadPool(int minIdle, int maxBusy)
   {
      this.setThreadFactory(null);

      this.busyWorkers = new AtomicInteger();
      this.idleWorkers = new AtomicInteger();
      this.aliveWorkers = new AtomicInteger();

      this.minIdleWorkers = minIdle;
      this.maxBusyWorkers = maxBusy;

      this.queue = new ConcurrentQueue<Runnable>(true);

      new Thread(new PoolMonitor()).start();
   }

   //

   protected void onIdleTimeout()
   {
      //
   }

   protected void onNewWorker()
   {
      //
   }

   public int busyWorkers()
   {
      return this.busyWorkers.get();
   }

   public int idleWorkers()
   {
      return this.idleWorkers.get();
   }

   public int aliveWorkers()
   {
      return this.aliveWorkers.get();
   }

   //

   volatile ThreadFactory factory;

   public void setThreadFactory(ThreadFactory factory)
   {
      if (factory == null)
      {
         factory = new ThreadFactory()
         {
            @Override
            public Thread newThread(Runnable r)
            {
               return new Thread(r);
            }
         };
      }

      this.factory = factory;
   }

   //

   volatile long idleTimeout = Long.MAX_VALUE;

   public void setWorkerTimeout(long timeout)
   {
      this.idleTimeout = timeout;
   }

   final ConcurrentQueue<Runnable> queue;

   public void put(Runnable task)
   {
      if (task == null)
         throw new NullPointerException();
      this.queue.produce(task);
   }

   class PoolMonitor implements Runnable
   {
      @Override
      public void run()
      {
         ThreadPool self = ThreadPool.this;

         while (true)
         {

            if (self.queue.isEmpty())
            {
               try
               {
                  Thread.sleep(10);
               }
               catch (InterruptedException exc)
               {
                  Thread.interrupted();
               }

               continue;
            }

            if (self.busyWorkers.get() >= self.maxBusyWorkers) // unsafe
            {
               continue;
            }

            self.aliveWorkers.incrementAndGet();
            self.onNewWorker();

            Worker worker = new Worker();
            ThreadFactory factory = self.factory;
            Thread t;
            if (factory == null)
               t = new Thread(worker);
            else
               t = factory.newThread(worker);
            t.start();
         }
      }
   }

   class Worker implements Runnable
   {
      @Override
      public void run()
      {
         ThreadPool self = ThreadPool.this;

         while (true)
         {
            self.idleWorkers.incrementAndGet();
            Runnable task = self.queue.consume(self.idleTimeout);
            int idlers = self.idleWorkers.decrementAndGet();

            if (task == null)
            {
               if (idlers < self.minIdleWorkers)
                  continue;
               break;
            }

            self.busyWorkers.incrementAndGet();
            try
            {
               task.run();
            }
            catch (Throwable exc)
            {
               exc.printStackTrace();
            }
            self.busyWorkers.decrementAndGet();
         }

         self.aliveWorkers.decrementAndGet();
         self.onIdleTimeout();
      }
   }
}