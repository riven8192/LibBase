/*
 * Created on 7 mei 2009
 */

package craterstudio.util.concur;

import craterstudio.util.HighLevel;

public class TaskProcessorManager implements Runnable
{
   private final TaskProcessor tp;

   public TaskProcessorManager(TaskProcessor tp)
   {
      this.tp = tp;
      this.minThreads = 0;
      this.maxThreads = Runtime.getRuntime().availableProcessors();
      this.interval = 250;
      this.maxQueueEmpty = 10 * 1000;
      this.maxQueueFilled = 1 * 1000;
   }

   public void launch()
   {
      Thread t = new Thread(this, "TaskProcessorManager");
      t.setDaemon(true);
      t.start();
   }

   //

   private volatile boolean verbose;

   public void setVerbose(boolean verbose)
   {
      this.verbose = verbose;
   }

   //

   private volatile long interval;

   public void setInterval(long interval)
   {
      this.interval = interval;
   }

   //

   private volatile int minThreads;
   private volatile int maxThreads;

   public void setThreadCountRange(int min, int max)
   {
      if ((min | max) < 0)
         throw new IllegalArgumentException();
      if (max == 0)
         throw new IllegalArgumentException();
      if (min > max)
         throw new IllegalArgumentException();

      this.minThreads = min;
      this.maxThreads = max;
   }

   //

   private volatile long maxQueueEmpty;
   private volatile long maxQueueFilled;

   public void setQueueTimeoutRange(long maxQueueEmpty, long maxQueueFilled)
   {
      this.maxQueueEmpty = maxQueueEmpty;
      this.maxQueueFilled = maxQueueFilled;
   }

   //

   private long queueFilledSince = Long.MAX_VALUE;
   private long queueEmptySince  = Long.MAX_VALUE;

   public void run()
   {
      while (true)
      {
         HighLevel.sleep(this.interval);

         int total = tp.threadCount();
         int queue = tp.queueCount();

         if (total > this.maxThreads)
         {
            this.tp.removeThread();
            
            if (this.verbose)
            {
               System.out.println(this.getClass().getSimpleName() + " :: " + this.toString());
            }
         }
         else if (total < this.minThreads)
         {
            this.tp.addThread();
            
            if (this.verbose)
            {
               System.out.println(this.getClass().getSimpleName() + " :: " + this.toString());
            }
         }
         else if (queue == 0)
         {
            if (this.handleEmptyQueue())
            {
               if (this.verbose)
               {
                  System.out.println(this.getClass().getSimpleName() + " :: " + this.toString());
               }
            }
         }
         else
         {
            if (this.handleFilledQueue())
            {
               if (this.verbose)
               {
                  System.out.println(this.getClass().getSimpleName() + " :: " + this.toString());
               }
            }
         }
      }
   }

   private boolean handleFilledQueue()
   {
      this.queueEmptySince = Long.MAX_VALUE;

      // it appears to be the first time the queue is filled
      if (this.queueFilledSince == Long.MAX_VALUE)
      {
         this.queueFilledSince = System.currentTimeMillis();

         return false;
      }

      long elapsed = System.currentTimeMillis() - this.queueFilledSince;

      // not filled long enough
      if (elapsed < this.maxQueueFilled)
      {
         return false;
      }

      // we reached the maximum thread count
      if (this.tp.threadCount() >= this.maxThreads)
      {
         return false;
      }

      this.tp.addThread();

      this.queueFilledSince = Long.MAX_VALUE;

      return true;
   }

   private boolean handleEmptyQueue()
   {
      this.queueFilledSince = Long.MAX_VALUE;

      // it appears to be the first time the queue is empty
      if (this.queueEmptySince == Long.MAX_VALUE)
      {
         this.queueEmptySince = System.currentTimeMillis();

         return false;
      }

      long elapsed = System.currentTimeMillis() - this.queueEmptySince;

      // not idle long enough
      if (elapsed < this.maxQueueEmpty)
      {
         return false;
      }

      // we reached the minimum thread count
      if (this.tp.threadCount() <= this.minThreads)
      {
         return false;
      }

      // don't remove if we're busy
      if (this.tp.busyCount() == this.tp.threadCount())
      {
         return false;
      }

      this.tp.removeThread();

      this.queueEmptySince = Long.MAX_VALUE;

      return true;
   }

   public String toString()
   {
      return this.tp.busyCount() + "/" + this.tp.threadCount() + " (+" + this.tp.queueCount() + ")";
   }
}
