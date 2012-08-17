/*
 * Created on 25 mei 2010
 */

package craterstudio.util.concur;

import java.util.Comparator;
import java.util.TreeSet;

import craterstudio.func.Filter;
import craterstudio.time.Clock;
import craterstudio.util.Asserts;
import craterstudio.util.HighLevel;

public class ScheduledTaskQueue
{
   final TreeSet<ScheduledTask> tree;

   public ScheduledTaskQueue()
   {
      this.tree = new TreeSet<ScheduledTask>(new ScheduledTaskComparator());

      this.launchThread();
   }

   //

   public void schedule(Runnable task)
   {
      this.schedule(task, 0L);
   }

   public void schedule(Runnable task, long msDelay)
   {
      if (msDelay < 0L)
      {
         throw new IllegalArgumentException();
      }

      this.scheduleAt(task, Clock.now() + msDelay);
   }

   //

   public void scheduleAt(Runnable task, long timestamp)
   {
      if (task == null)
      {
         throw new NullPointerException();
      }

      this.scheduleImpl(new ScheduledTask(task, timestamp));
   }

   public <T> void scheduleLoop(final long timestamp, final long interval, final T item, final Filter<T> repeatCondition)
   {
      Asserts.assertNotNull(item);
      Asserts.assertNotNull(repeatCondition);

      Runnable loop = new Runnable()
      {
         private long increment = timestamp;

         @Override
         public void run()
         {
            if (repeatCondition.accept(item))
            {
               this.increment += interval;

               scheduleImpl(new ScheduledTask(this, this.increment));
            }
         }
      };

      this.scheduleImpl(new ScheduledTask(loop, timestamp));
   }

   void scheduleImpl(ScheduledTask sched)
   {
      synchronized (this.tree)
      {
         this.tree.add(sched);

         this.tree.notify();
      }
   }

   public void shutdown()
   {
      this.scheduleImpl(null);
   }

   private final void launchThread()
   {
      new Thread(new Runnable()
      {
         @Override
         public void run()
         {
            while (true)
            {
               ScheduledTask scheduled;

               synchronized (tree)
               {
                  while (tree.isEmpty())
                  {
                     // wakes up on new task
                     HighLevel.wait(tree);
                  }

                  scheduled = tree.first();
                  if (scheduled == null)
                     break;

                  long toWait = scheduled.timestamp - Clock.now();
                  if (toWait > 0L)
                  {
                     // wake up on new task or first task pending
                     HighLevel.wait(tree, toWait);
                     continue;
                  }
               }

               tree.pollFirst();

               try
               {
                  scheduled.task.run();
               }
               catch (Throwable exc)
               {
                  exc.printStackTrace();
               }
            }
         }
      }).start();
   }

   //

   static class ScheduledTask
   {
      public final Runnable task;
      public final long     timestamp;

      public ScheduledTask(Runnable task, long timestamp)
      {
         this.task = task;
         this.timestamp = timestamp;
      }
   }

   static class ScheduledTaskComparator implements Comparator<ScheduledTask>
   {
      @Override
      public int compare(ScheduledTask a, ScheduledTask b)
      {
         return (a.timestamp < b.timestamp) ? -1 : +1;
      }
   }
}