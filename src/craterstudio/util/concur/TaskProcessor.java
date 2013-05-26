/*
 * Created on 21 jan 2008
 */

package craterstudio.util.concur;

import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import craterstudio.util.HighLevel;

public class TaskProcessor
{
   private static int instanceCounter;

   public TaskProcessor()
   {
      this(Runtime.getRuntime().availableProcessors());
   }

   public TaskProcessor(int threadCount)
   {
      this("TaskProcessor#" + (instanceCounter++), Thread.NORM_PRIORITY, threadCount);
   }

   public TaskProcessor(String name, int threadPriority)
   {
      this(name, threadPriority, Runtime.getRuntime().availableProcessors());
   }

   public TaskProcessor(String name, int threadPriority, int threadCount)
   {
      this.name = name;
      this.threadPriority = threadPriority;

      this.queue = new ConcurrentQueue<Runnable>(false);

      for (int i = 0; i < threadCount; i++)
         this.addThread();
   }

   private final String            name;
   private int                     threadPriority;
   final ConcurrentQueue<Runnable> queue;
   final AtomicInteger             workerCount       = new AtomicInteger();
   final AtomicInteger             addedWorkers      = new AtomicInteger();

   final AtomicInteger             addedTaskCount    = new AtomicInteger();
   final AtomicInteger             startedTaskCount  = new AtomicInteger();
   final AtomicInteger             finishedTaskCount = new AtomicInteger();

   public void addThread()
   {
      this.workerCount.incrementAndGet();

      TaskProcessorHandler tph = new TaskProcessorHandler();
      Thread thread = new Thread(tph);
      thread.setName(name + "[#" + addedWorkers.incrementAndGet() + "]");
      thread.setPriority(this.threadPriority);
      thread.setDaemon(false);
      thread.start();
   }

   public void removeThread()
   {
      this.put(new ShutdownTask());
   }

   //

   public int threadCount()
   {
      return this.workerCount.get();
   }

   public int busyCount()
   {
      return this.startedTaskCount.get() - this.finishedTaskCount.get();
   }
   
   public int idleCount()
   {
      return this.threadCount() - this.busyCount();
   }

   public int queueCount()
   {
      return this.queue.size();
   }

   //

   public Task putAsTask(Runnable task)
   {
      Task t = new Task(task);
      this.put(t);
      return t;
   }

   public void put(Runnable task)
   {
      this.addedTaskCount.incrementAndGet();
      this.queue.produce(task);
   }

   //

   public void shutdown()
   {
      this.shutdown(false);
   }

   public void shutdown(boolean waitFor)
   {
      int awc = this.workerCount.get() * 10;
      for (int i = 0; i < awc; i++)
      {
         this.removeThread();
      }

      if (waitFor)
      {
         while (this.workerCount.get() != 0)
         {
            HighLevel.sleep(10);
         }
      }
   }

   public void waitFor()
   {
      while (this.addedTaskCount.get() != this.finishedTaskCount.get())
      {
         HighLevel.sleep(10);
      }
   }

   public void yieldFor()
   {
      while (this.addedTaskCount.get() != this.finishedTaskCount.get())
      {
         Thread.yield();
      }
   }

   class TaskProcessorHandler implements Runnable
   {
      @Override
      public void run()
      {
         while (true)
         {
            Runnable task = TaskProcessor.this.queue.consume();

            TaskProcessor.this.startedTaskCount.incrementAndGet();

            try
            {
               task.run();
            }
            catch (Throwable exc)
            {
               exc.printStackTrace();
            }
            finally
            {
               TaskProcessor.this.finishedTaskCount.incrementAndGet();
            }

            if (task instanceof ShutdownTask)
            {
               break;
            }
         }

         TaskProcessor.this.workerCount.decrementAndGet();
      }
   }

   public class Task implements Runnable
   {
      final Runnable task;
      final SimpleCountDownLatch started, done;
      Throwable            error;

      public Task(Runnable task)
      {
         this.task = task;
         this.started = new SimpleCountDownLatch();
         this.done = new SimpleCountDownLatch();
      }

      public void run()
      {
         this.started.countDown();

         try
         {
            this.task.run();
         }
         catch (Throwable t)
         {
            error = t;
            t.printStackTrace();
         }
         finally
         {
            this.done.countDown();
         }
      }

      public void waitForStart()
      {
         this.started.await();
      }

      public void waitForDone()
      {
         this.done.await();
      }

      public boolean isDone()
      {
         return this.isDone();
      }

      public boolean hasError()
      {
         return this.error != null;
      }

      public Throwable getError()
      {
         if (!this.hasError())
            throw new NoSuchElementException();
         return this.error;
      }
   }

   class ShutdownTask implements Runnable
   {
      public SimpleCountDownLatch exec = new SimpleCountDownLatch();

      @Override
      public void run()
      {
         exec.countDown();
      }
   }
}