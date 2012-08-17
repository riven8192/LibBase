/*
 * Created on 20 nov 2008
 */

package craterstudio.util.concur;

import java.util.concurrent.atomic.AtomicReference;

import craterstudio.misc.Result;

public class TaskQueue
{
   final SimpleBlockingQueue<Runnable> queue;

   public TaskQueue()
   {
      this.queue = new SimpleBlockingQueue<Runnable>();
   }

   private Thread thread;

   public void launch()
   {
      this.thread = new Thread(new Runnable()
      {
         @Override
         public void run()
         {
            do
            {
               Runnable task = TaskQueue.this.queue.take();

               if (task == null)
               {
                  break;
               }

               try
               {
                  task.run();
               }
               catch (Exception exc)
               {
                  exc.printStackTrace();
               }
            }
            while (true);
         }
      }, "RunnableQueue");
      thread.start();
   }

   public boolean isOnThread()
   {
      return this.thread == Thread.currentThread();
   }

   public void later(Runnable task)
   {
      if (task == null)
         throw new NullPointerException();
      this.queue.put(task);
   }

   public <T> T sync(final Result<T> task)
   {
      if (task == null)
         throw new NullPointerException();

      if (this.isOnThread())
         return task.get();

      final AtomicReference<T> ref = new AtomicReference<T>();

      this.sync(new Runnable()
      {
         @Override
         public void run()
         {
            ref.set(task.get());
         }
      });

      return ref.get();
   }

   public void sync(final Runnable task)
   {
      if (task == null)
         throw new NullPointerException();

      if (this.isOnThread())
      {
         task.run();
         return;
      }

      final OneTimeLock notifyDone = new OneTimeLock();

      this.queue.put(new Runnable()
      {
         @Override
         public void run()
         {
            try
            {
               task.run();
            }
            finally
            {
               notifyDone.release();
            }
         }
      });

      notifyDone.waitFor();
   }

   public OneTimeLock getBarrier()
   {
      final OneTimeLock lock = new OneTimeLock();

      this.later(new Runnable()
      {
         @Override
         public void run()
         {
            lock.release();
         }
      });

      return lock;
   }

   public void terminateLater()
   {
      this.queue.put(null);
   }
}
